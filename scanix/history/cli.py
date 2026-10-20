"""Explicit local history commands; JSON quoting protects terminal control characters."""
import json
import sys


def register(sub):
    history=sub.add_parser('history',help='optional private SQLite observations and conservative comparisons')
    history.add_argument('--db',required=True,help='existing private history SQLite file')
    commands=history.add_subparsers(dest='history_command',required=True)
    listing=commands.add_parser('list',help='recent scan summaries, newest first')
    listing.add_argument('--limit',type=int,default=20)
    show=commands.add_parser('show',help='configuration, versions and coverage; optional streamed rows')
    show.add_argument('scan_id');show.add_argument('--results',action='store_true')
    diff=commands.add_parser('diff',help='stream observed state/service/evidence changes; absence is not removal')
    diff.add_argument('previous');diff.add_argument('current')
    delete=commands.add_parser('delete',help='logically delete one scan and its observations; not secure erasure')
    delete.add_argument('scan_id')
    prune=commands.add_parser('prune',help='keep newest N scans including partial ones; not secure erasure')
    prune.add_argument('--keep',type=int,required=True)


def emit(value):
    print(json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')))


def run(args):
    try:
        from .store import History
        with History(args.db) as history:
            if args.history_command=='list':
                for summary in history.list(args.limit):emit(summary)
            elif args.history_command=='show':
                emit({'type':'scan',**history.show(args.scan_id)})
                if args.results:
                    for key,record in history.records(args.scan_id):
                        emit({'type':'result','endpoint':json.loads(key),'record':record})
            elif args.history_command=='diff':
                for change in history.compare(args.previous,args.current):emit(change)
            elif args.history_command=='delete':
                history.delete(args.scan_id);emit({'deleted_scan':args.scan_id})
            elif args.history_command=='prune':emit({'deleted_scans':history.prune(args.keep)})
        return 0
    except Exception as exc:
        print('History operation failed: '+type(exc).__name__+'; no clean result',file=sys.stderr)
        return 1
