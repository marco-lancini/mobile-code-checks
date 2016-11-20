#! /usr/bin/env python

"""Android Code Checks

Run against a folder: python tester.py -f /folder/
Run a diff:           python tester.py -d1 folder_old/ -d2 folder_new/
"""

import os
import sys
import re
import logging
import logging.config
import argparse
import subprocess
from pprint import pprint

MODULE_NAME = 'Android_Checks'
MODULE_DESCRIPTION = 'Static analyzer for Android codebases'
LOG_PATH = os.path.dirname(os.path.realpath(__file__))
LOG_FILE = os.path.join(LOG_PATH, '%s.debug' % MODULE_NAME)

# ========================================================================================
# LOGGER
# ========================================================================================
logger = logging.getLogger('%s.log' % MODULE_NAME)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'standard': {
            'format': '%(message)s',
        },
        'verbose': {
            'format': '[%(asctime)s][%(levelname)s]\t%(name)s %(filename)s:%(funcName)s:%(lineno)d | %(message)s',
            'datefmt': '%H:%M:%S',
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logutils.colorize.ColorizingStreamHandler',
            'formatter': 'standard',
        },
        'file_debug': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': LOG_FILE,
            'formatter': 'standard'
        },
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file_debug'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
}
logging.config.dictConfig(LOGGING)


# ========================================================================================
# STATIC ANALYZER
# ========================================================================================
class StaticAnalyzer(object):
    GREP_OPTS='''-ir -H --include="*.java" --include="*.js" --include="*.json" --include="*.strings" --exclude-dir=.{git,hg,svn}'''
    AWK='''| awk -F":" '{print $1}'| sort | uniq'''

    def parse_cl(self):
        parser = argparse.ArgumentParser(description='%s, %s.' % (MODULE_NAME, MODULE_DESCRIPTION))
        parser.add_argument(
            '-f',
            '--folder',
            help='Folder to analyze.')
        parser.add_argument(
            '-d1',
            '--diff1',
            help='First folder to diff.')
        parser.add_argument(
            '-d2',
            '--diff2',
            help='Second folder to diff.')
        self.opts = parser.parse_args()

    def __repr__(self):
        return '%s%s' % (MODULE_NAME, MODULE_DESCRIPTION)

    def __init__(self, *args, **kwargs):
        self.parse_cl()

        if not self.opts.folder and (not self.opts.diff1 or not self.opts.diff2):
            raise Exception('Folder needed!')

        # Clean output file
        open(LOG_FILE, 'w').close()

        # Get type of analysis
        if self.opts.folder:
            self.TYPE_FOLDER = True
            self.diff = None
        else:
            self.TYPE_FOLDER = False
            self.diff = self.make_diff()

        # Run checks
        self.run()

    # ====================================================================================
    # UTILS
    # ====================================================================================
    def make_diff(self):
        logger.info("Computing diff...")
        # Run diff
        cmd = "diff -qr {f1} {f2}".format(f1=self.opts.diff1, f2=self.opts.diff2)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        # Sort
        res = filter(None, out.split('\n'))
        modified = []
        for line in res:
            if 'differ' in line:
                modified.append(line.split()[-2])
            elif self.opts.diff2 in line:
                temp = line[len("Only in "):]
                temp = temp.replace(": ", "/")
                modified.append(temp)
        return modified

    def grep(self, what, awk=False):
        def do_grep(what, where, select):
            cmd = "grep {opts} {what} {where} {select}".format(opts=self.GREP_OPTS, 
                                                               what=what, where=where, 
                                                               select=select)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            return filter(None, output.split('\n'))
        # Filter with AWK          
        select = self.AWK if awk else ""
        # Where to search for
        if self.TYPE_FOLDER:
            where = self.opts.folder
            return do_grep(what, where, select)
        else:
            to_check = []
            for d in self.diff:
                where = d
                to_check.extend(do_grep(what, where, select))
            return to_check

    def print_findings(self, findings):
        for f in findings:
            logger.warning("+[%s] line %s \t -> %s" % (f['name'], f['linenum'], f['line']))

    def is_comment(self, line):
        return line.startswith('//') or line.startswith('/*') or line.startswith('*') or line.startswith('@')

    def extract_lines(self, fnames, searchfor, casesensitive=False):
        found = []
        for name in fnames:
            try:
                with open(name, "rb") as fp:
                    prev = ''
                    for i, line in enumerate(fp):
                        line = line.strip()
                        if not self.is_comment(line):
                            if searchfor.lower() in line.lower():
                                found.append({'name': name, 'linenum': i+1, 'line': line, 'prev': prev})
                        prev = line
            except:
                pass
        return found

    # ====================================================================================
    # CHECKS
    # ====================================================================================
    def logging(self):
        logger.info('* LOGGING')
        res = self.grep("'import android.util.log'", awk=True)
        temp = self.extract_lines(res, searchfor='Log.', casesensitive=True)
        findings = [f for f in temp if 'RMLog' not in f['line']]
        self.print_findings(findings)

    def stack_trace(self):
        logger.info('* STACK TRACE')
        res = self.grep("-P '(?<!log)\.printstacktrace'", awk=True)
        findings = self.extract_lines(res, searchfor='printstacktrace')
        self.print_findings(findings)

    def http_urls(self):
        logger.info('* HTTP URLs')
        res = self.grep("'http://'", awk=True)
        findings = self.extract_lines(res, searchfor='http://')
        self.print_findings(findings)

    def webview_js(self):
        logger.info('* Webview with javascript enabled')
        res = self.grep("-P '.setJavaScriptEnabled\((?!false)'", awk=True)
        findings = self.extract_lines(res, searchfor='setJavaScriptEnabled')
        self.print_findings(findings)

    def webview_handler_proceed(self):
        logger.info('* Checking for handler.proceed')
        res = self.grep("handler.proceed", awk=True)
        findings = self.extract_lines(res, searchfor='handler.proceed')
        self.print_findings(findings)

    def file_handlers(self):
        logger.info('* New file handler (File*, Buffer*)')
        res = self.grep("'new File\|new Buffer'", awk=True)
        t1 = self.extract_lines(res, searchfor='new File')
        t2 = self.extract_lines(res, searchfor='new Buffer')
        findings = t1 + t2
        self.print_findings(findings)

    def file_sql(self):
        logger.info('* SQLite')
        res = self.grep("'SQL'", awk=True)
        findings = self.extract_lines(res, searchfor='SQL')
        self.print_findings(findings)

    def file_cache(self):
        logger.info('* CACHE')
        res = self.grep("'Cache'", awk=True)
        findings = self.extract_lines(res, searchfor='Cache')
        self.print_findings(findings)

    def run(self):
        logger.info("Running checks...")
        self.logging()
        self.stack_trace()
        self.http_urls()
        self.webview_js()
        self.webview_handler_proceed()
        self.file_handlers()
        self.file_sql()
        #self.file_cache()

# ========================================================================================
# MAIN
# ========================================================================================
if __name__ == '__main__':
    s = StaticAnalyzer()
    
