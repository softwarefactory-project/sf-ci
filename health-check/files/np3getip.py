import json, subprocess, time, sys
name = sys.argv[1]
att = 0
while att < 30:
    att += 1
    try:
        cmd = "openstack server list -f json"
        ret = json.loads(subprocess.check_output(cmd, shell=True))
        ret = [e["Networks"] for e in ret if e["Name"].startswith(name)][0]
        print ret.split(",")[-1].strip()
        sys.exit(0)
    except Exception:
        time.sleep(10)
        pass
sys.exit(1)
