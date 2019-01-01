#!/usr/bin/python3
import time
import traceback
def test():
    try:
        with open('last-login-time.txt') as o:
            last_login = float(o.read().strip())
    except (ValueError, FileNotFoundError):
        last_login = time.time()
        traceback.print_exc()

    actions = {10:lambda: print('10 seconds passed!'), 20:lambda: print('20 seconds passed!'), 30:lambda: print('30 seconds passed!')}

    relative_time = time.time()-last_login

    try:
        with open('latest-relative-time.txt') as o:
            latest_relative_time = float(o.read().strip())
    except (ValueError, FileNotFoundError):
        latest_relative_time=0
    for i in sorted(actions):
        if i>latest_relative_time:
            if i<relative_time:
                actions[i]()
                with open('latest-relative-time.txt','w') as o:
                    o.write(str(relative_time))

if __name__ == '__main__':
    while 1:
        test()
