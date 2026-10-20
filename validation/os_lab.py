"""Optional Linux namespace OS evidence validation; raw artifacts stay private."""
import hashlib
import platform
import re
import signal
import subprocess
import time


def validate(output, parent_netns):
    from validation.privileged_lab import assert_isolated, V4, V6, record
    assert_isolated(parent_netns, ('lo','sxscan'))
    from scapy.all import IP, IPv6, TCP, rdpcap
    from scanix.core.models import ScanConfig, ResolvedTarget
    from scanix.core.scanner import scan_target
    result={'status':'failed','checks':[],'families':[],
            'ground_truth':'owned Linux kernel peer in separate namespace',
            'kernel_major':platform.release().split('.')[0],
            'topology':'IPv4/IPv6 veth, no external default route, MTU1500'}
    def check(name,passed):result['checks'].append({'name':name,'passed':bool(passed)})
    path=output/'os-evidence.pcap';log=output/'os-evidence-capture.log'
    with log.open('w') as stream:
        capture=subprocess.Popen(['tcpdump','-n','--immediate-mode','-U','-s','256','-c','10000',
            '-i','sxscan','-w',str(path)],stdout=subprocess.DEVNULL,stderr=stream)
        reports=[]
        try:
            deadline=time.monotonic()+5
            while 'listening on' not in log.read_text():
                if capture.poll() is not None or time.monotonic()>=deadline:
                    raise RuntimeError('OS lab capture unavailable')
                time.sleep(.02)
            for version,address in ((4,V4[1]),(6,V6[1])):
                config=ScanConfig(address,(19000,19001),method='syn',os_detect=True,
                    concurrency=1,per_host=1,retries=0,adaptive=False,timeout=.4,rate=20)
                report=scan_target(config,endpoint=ResolvedTarget(address,'IPv'+str(version)))
                reports.append((version,report))
                record(output/('os-ipv'+str(version)+'.json'),report.to_dict())
            time.sleep(.1)
        finally:
            if capture.poll() is None:capture.send_signal(signal.SIGINT)
            capture.wait(timeout=5)
    packets=rdpcap(str(path))
    drops=re.search(r'([0-9]+) packets dropped by kernel',log.read_text())
    check('capture-loss-measured-zero',drops is not None and int(drops[1])==0)
    for version,report in reports:
        net=IP if version==4 else IPv6
        opened=next(r for r in report.results if r.port==19000)
        closed=next(r for r in report.results if r.port==19001)
        check('states-preserved-v'+str(version),report.completion_status=='complete' and opened.state=='open' and closed.state=='closed')
        check('closed-inconclusive-v'+str(version),closed.evidence['os_detection']['status']=='inconclusive')
        replies=[p for p in packets if net in p and TCP in p and p[net].src==(V4 if version==4 else V6)[1]
                 and p[TCP].sport==19000 and int(p[TCP].flags)&0x3f==0x12]
        check('remote-synack-observed-v'+str(version),len(replies)==1)
        features=opened.evidence.get('remote_tcp',{})
        if replies:
            wire=replies[0]
            probes=[p for p in packets if net in p and TCP in p and p[net].dst==wire[net].src
                    and p[TCP].dport==19000 and p[TCP].sport==wire[TCP].dport and int(p[TCP].flags)==2]
            check('independent-correlation-v'+str(version),len(probes)==1 and wire[TCP].ack==(probes[0][TCP].seq+1)%2**32)
            opts=dict(wire[TCP].options)
            check('captured-feature-equality-v'+str(version),features.get('observed_hop_limit')==int(wire[net].ttl if version==4 else wire[net].hlim)
                and features.get('tcp_window')==int(wire[TCP].window) and features.get('mss')==opts.get('MSS')
                and features.get('dont_fragment')==(bool(int(wire[net].flags)&2) if version==4 else None))
        detection=opened.evidence['os_detection']
        check('no-reliable-os-claim-v'+str(version),opened.os is None and detection['authenticated'] is False)
        if version==4:
            check('original-experimental-profile-matches',detection['status']=='experimental_match')
        else:
            check('unsupported-ipv6-profile-inconclusive',detection['reason']=='unsupported_fingerprint_family')
        result['families'].append({'version':version,'features':features,'detection':detection})
    result['capture_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    result['packet_count']=len(packets)
    result['kernel_drops']=int(drops[1]) if drops else None
    result['status']='passed' if all(c['passed'] for c in result['checks']) else 'failed'
    record(output/'os-summary.json',result)
    return result
