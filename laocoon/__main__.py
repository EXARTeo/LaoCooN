"""python -m laocoon memory --db PATH {stats,list,show,confirm,reject,delete,add,export,import}  (⑥ attack memory)"""
import sys

from .memory import main as memory_main


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["memory"]:
        return memory_main(argv[1:])
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main())
