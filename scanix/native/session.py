"""Durable native port classification followed by separately paced enrichment."""
from concurrent.futures import CancelledError
from dataclasses import replace
import os
import shutil
import threading
import time

from ..core.models import ScanReport, ScanResult, utc_now
from ..core.timing import Runtime
from .adapter import scan_native
from .checkpoint import Checkpoint, ResultStream, manifest


def scan_session(config, plan, checkpoint, stream_file, *, resume=False, shard=(0,1),
                 binary=None, stop=None, progress=None):
    stop = stop or threading.Event()
    targets = list(plan)
    command = binary or os.environ.get('SCANIX_NATIVE_ENGINE') or shutil.which('scanix-engine')
    if command is None:
        raise FileNotFoundError('native engine executable not configured')
    command = shutil.which(command) or command
    identity = manifest(config,plan,targets,command,*shard)
    started = time.monotonic()
    with Checkpoint(checkpoint,identity,config,targets,resume=resume,index=shard[0],count=shard[1]) as state:
        prior = state.completed
        unknown_metrics=state.metrics_unknown()
        stream = ResultStream(stream_file,{'fingerprint':identity['fingerprint'],
                                         'restored_results':prior,'shard_index':shard[0],
                                         'shard_count':shard[1],'wire_protocol':3})
        try:
            state.begin()
            for id, record in state.records():
                stream.result(id,record)
            def save(row):
                # Commit before publishing. A stream failure cannot lose the durable result.
                record=state.add(row)
                stream.result(record['evidence']['work_id'],record)
            remaining=state.selection.remaining
            budget=config.engine_timeout-(time.monotonic()-started)
            guard=1/(config.rate or {'connect':100,'syn':10}[config.method]) if prior and remaining else 0
            if remaining and guard < budget and not stop.wait(guard):
                run_config=replace(config,service_detect=False,engine_timeout=max(.1,budget-guard))
                report=scan_native(run_config,plan,stop,binary=command,
                                   progress=progress,selection=state.selection,on_result=save,retain=False)
                report.configuration=config
            else:
                status='interrupted' if stop.is_set() else 'failed' if remaining else 'complete'
                report=ScanReport(config,completed_probes=0,requested_probes=remaining,completion_status=status,
                                  implementation={'engine':'native','wire_protocol':3,
                                                  'engine_version':None,'session_skipped':
                                                  'no_remaining_ports' if not remaining else 'budget_or_cancellation'})
                if remaining and not stop.is_set():report.issues.append({'reason':'resume_rate_guard_or_session_budget_exhausted'})
            session_completed=state.completed-prior
            metrics=report.implementation.get('metrics',{})
            if session_completed and (not metrics or config.method=='syn' and metrics.get('capture_drops') is None):
                state.mark_metrics_unknown();unknown_metrics=True
            if any(metrics.get(key) for key in ('send_errors','queue_drops','capture_drops')):
                state.set_loss()
            if config.service_detect and not stop.is_set():
                from ..service.engine import enrich_results
                from ..service.registry import load_registry
                report.probe_database_version=load_registry().version
                runtime=Runtime(config)
                # Protect the transition from the child rate domain to this separate stage.
                runtime.limiter.acquire(stop)
                for id, record in state.records():
                    detection=record.get('service_detection')
                    if record['state']!='open' or detection and detection.get('status') not in ('interrupted','not_attempted'):
                        continue
                    if stop.is_set():break
                    if time.monotonic()-started >= config.engine_timeout:
                        report.completion_status='failed'
                        report.issues.append({'reason':'enrichment_session_budget_exhausted'})
                        break
                    row=ScanResult(**{**record,'original_targets':tuple(record['original_targets']),
                                      'service_detection':None})
                    # One endpoint at a time bounds memory and all existing per-host/global limits.
                    budget=max(.1,min(config.service_timeout or (3 if config.service_profile=='quick' else 8),
                                      config.engine_timeout-(time.monotonic()-started)))
                    enrich_results([row],replace(config,service_timeout=budget),stop,runtime)
                    stream.result(id,state.update_enrichment(id,row))
            report.requested_probes=state.selection.requested
            report.completed_probes=state.completed
            report.scope=plan.preview(config.ports,config.method,limit=0)
            report.implementation['continuation']={'checkpoint_format':1,'fingerprint':identity['fingerprint'],
                'restored_results':prior,'new_results':session_completed,'shard_index':shard[0],
                'shard_count':shard[1],'full_scope_pairs':state.selection.total,
                'retained_result_objects':0,'coverage_loss':True if state.has_loss() else None if unknown_metrics else False,
                'prior_session_metrics_unknown':unknown_metrics,
                'storage_commit_seconds':state.commit_seconds,'storage_commits':state.commit_count}
            if unknown_metrics:
                report.issues.append({'reason':'checkpoint_session_metrics_unavailable'})
            if state.has_loss():
                report.completion_status='failed'
                report.issues.append({'reason':'checkpoint_contains_prior_transmission_or_capture_loss'})
            if stop.is_set():report.completion_status='interrupted'
            report.finished_at=utc_now()
            summary=report.to_dict()
            # Fixed-size summary: expanded config/scope live in caller input, not this stream frame.
            summary={key:summary[key] for key in ('schema_version','started_at','finished_at','completion_status',
                      'requested_ports','completed_ports','incomplete','implementation','issues','probe_database_version')}
            summary['elapsed_including_storage_seconds']=time.monotonic()-started
            summary['new_results_per_second']=session_completed/max(summary['elapsed_including_storage_seconds'],1e-9)
            state.finish(summary)
            stream.write({'type':'summary',**summary})
            return report
        except CancelledError:
            stop.set()
            raise
        finally:
            stream.close()
