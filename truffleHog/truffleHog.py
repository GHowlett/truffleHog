#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import json
import stat
import re
from git import Repo
from gibberishDetector import is_gibberish

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    args = parser.parse_args()
    try:
        project_path = tempfile.mkdtemp()
        Repo.clone_from(args.git_url, project_path, mirror=True)
        output = find_strings(project_path, args.output_json)
    finally:
        shutil.rmtree(project_path, onerror=del_rw)


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def find_strings(dir, printJson=False):
    entropicDiffs = []
    repo = Repo(dir)
    already_searched = set()

    if printJson: print('[')

    for branch in repo.branches:
        branch_name = branch.name

        prev_commit = None
        for curr_commit in repo.iter_commits(branch.commit): # TODO: exclude merge commits
            if not prev_commit:
                pass
            else:
                #avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                # diff = repo.git.diff(prev_commit, curr_commit, p=True)
                diffs = prev_commit.diff(curr_commit, create_patch=True, unified=0)
                for diff in diffs:
                    #print i.a_blob.data_stream.read()
                    diffstr = diff.diff.decode('utf-8', errors='replace')
                    if diffstr.startswith("Binary files"):
                        continue
                    findings = {}
                    lines = diffstr.split("\n")
                    baseline = 0;
                    for i,line in enumerate(lines):
                        if re.match(r"@@ -\d*,\d* \+\d*,\d* @@", line):
                            baseline = int(re.findall(r'\d*,\d*', line)[0].split(',')[0])
                            continue
                        elif line.startswith('-'): # only report when secrets are added, not removed
                            continue
                        for word in line.split():
                            base64_strings = get_strings_of_set(word, BASE64_CHARS)
                            hex_strings = get_strings_of_set(word, HEX_CHARS)
                            for string in base64_strings:
                                b64Entropy = shannon_entropy(string, BASE64_CHARS)
				# is_gibberish check reduces false positives with markov chain. 
				# false negative unlikely if str is truly high-entropy.
                                if b64Entropy > 4.5 and is_gibberish(string): 
                                    findings[string] = findings.get(string,[]) + [i]
                                    diffstr = diffstr.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                            for string in hex_strings:
                                hexEntropy = shannon_entropy(string, HEX_CHARS)
                                if hexEntropy > 3 and is_gibberish(string):
                                    findings[string] = findings.get(string,[]) + [i]
                                    diffstr = diffstr.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                    if len(findings) > 0:
                        commit_time =  datetime.datetime.fromtimestamp(curr_commit.committed_date);
                        entropicDiff = {}
                        entropicDiff['date'] = commit_time.isoformat()
                        entropicDiff['author'] = {'name': curr_commit.author.name, 'email': curr_commit.author.email}
                        entropicDiff['branch'] = branch_name
                        entropicDiff['commit'] = curr_commit.message.strip()
                        entropicDiff['hash'] = curr_commit.hexsha
                        entropicDiff['file'] = diff.b_path # TODO: make sure this is the correct filename for associated commit hash
                        entropicDiff['diff'] = diff.diff.decode('utf-8', errors='replace')
                        entropicDiff['stringsFound'] = findings.keys() # TODO: remove this at major version update, deprecated by new 'findings' structure
                        entropicDiff['findings'] = findings # a dictionary mapping found strings to a list of line numbers where they were found
                        entropicDiffs.append(entropicDiff)
                        if printJson:
                            if len(entropicDiffs) > 1: print(',')
                            sys.stdout.write(json.dumps(entropicDiff, sort_keys=True, indent=4))
                            sys.stdout.flush()
                        else:
                            print(bcolors.OKGREEN + "Date: " + commit_time.strftime('%Y-%m-%d %H:%M:%S') + bcolors.ENDC)
                            print(bcolors.OKGREEN + "Author: " + curr_commit.author.email + bcolors.ENDC)
                            print(bcolors.OKGREEN + "Branch: " + branch_name + bcolors.ENDC)
                            print(bcolors.OKGREEN + "Commit: " + curr_commit.message.strip() + bcolors.ENDC)
                            print(bcolors.OKGREEN + "Hash: " + curr_commit.hexsha + bcolors.ENDC)
                            print(bcolors.OKGREEN + "File: " + diff.b_path + bcolors.ENDC)
                            print('\n' + diffstr)

            prev_commit = curr_commit

    if printJson: print('\n]')
    return entropicDiffs

if __name__ == "__main__":
    main()

