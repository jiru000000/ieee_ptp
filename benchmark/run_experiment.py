#!/usr/bin/env python

import os
from subprocess import call, Popen, PIPE
import time
import json
import argparse
from switch import BMV2Switch
from load_gen import SendB2B

assert os.environ.get('P4BENCHMARK_ROOT')
assert os.environ.get('PYTHONPATH')
P4BENCHMARK_ROOT = os.environ.get('P4BENCHMARK_ROOT')
P4C = os.path.join(P4BENCHMARK_ROOT, 'p4c-bm/p4c_bm/__main__.py')

from packet_modification.bm_modification import benchmark_modification

def run_with_load(load=None, count=100000):
    sw = BMV2Switch(json_path='output/main.json', commands_path='output/commands.txt')
    sender = SendB2B(pcap_path='output/test.pcap', count=count)

    sw.start()
    time.sleep(1)
    sender.run()
    sw.kill()

    sent, recv, tput = sender.send_stats()
    return (sent, recv, tput, sender.results())

def clean_results(results):
    if len(results) < 4: return results
    return results[2:-1]

def dump_tsv(l, out_path):
    out = '\n'.join(map(lambda r: '\t'.join(map(lambda x: '%g'%x, r)), l))
    with open(out_path, 'w') as f:
        f.write(out)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Load Experiment Runner')
    parser.add_argument('json_file', help='path to json file describing experiment', type=str)
    args = parser.parse_args()

    # Load the conf for this experiment
    assert os.path.isfile(args.json_file)
    with open(args.json_file, 'r') as f:
        conf = json.load(f)
        assert type(conf) is dict

    # Create the directory we will run in
    exp_dir_path = os.path.dirname(args.json_file)
    exp_out_path = os.path.join(exp_dir_path, 'out')
    if os.path.exists(exp_out_path):
        assert os.path.isdir(exp_out_path)
    else:
        os.mkdir(exp_out_path)
    os.chdir(exp_out_path)

    assert 'type' in conf

    # Generate the P4 program, test pcap, etc.
    if conf['type'] == 'mod':
        assert 'operations' in conf
        assert 'fields' in conf
        ret = benchmark_modification(int(conf['operations']), int(conf['fields']), 'mod')
        assert (ret == True)
        prog = 'main'
        with open('p4c.log', 'w+') as out:
            p = Popen([P4C, 'output/%s.p4' % prog , '--json', 'output/%s.json' % prog],
                stdout=out, stderr=out)
            p.wait()
            assert (p.returncode == 0)
    else:
        assert False, "unknown experiment type: " + conf['type']

    count = 100000
    if 'count' in conf: count = int(conf['count'])

    # Run the experiment with the switch and load generator
    sent, recv, tput, results = run_with_load(count=count)

    # Save the results
    lost = sent - recv
    dump_tsv(clean_results(results), 'results.tsv')
    dump_tsv([[sent, recv, lost, tput]], 'load_stats.tsv')
