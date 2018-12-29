#!/usr/bin/python3
import time
try:
    with open('last-login-time.txt') as o:
        last_login = float(o.read().strip())
except FileNotFoundError:
    last_login = time.time()

try:
    with open('done-actions.txt') as o:
        done_actions = [int(i.strip()) for i in o if i]
except FileNotFoundError:
    done_actions=[]
actions = {10:lambda: print('10 seconds passed!'), 20:lambda: print('20 seconds passed!'), 30:lambda: print('30 seconds passed!')}

relative_time = time.time()-last_login

try:
    with open('latest-relative-time.txt') as o:
        latest_relative_time = float(o.read().strip())
except FileNotFoundError:
    latest_relative_time=0
for i in sorted(actions):
    if i>latest_relative_time:
        if i<relative_time:
            actions[i]()
            with open('latest-relative-time.txt','w') as o:
                o.write(str(relative_time))
