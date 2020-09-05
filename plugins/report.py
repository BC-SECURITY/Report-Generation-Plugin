""" An example of a plugin. """
from __future__ import print_function

from lib.common.plugins import Plugin
from jinja2 import Environment, FileSystemLoader
from tabulate import tabulate
from xhtml2pdf import pisa
from .attack import Plugin
from md2pdf.core import md2pdf
import lib.common.helpers as helpers
import threading
import sqlite3
import sys

# Overwrites the Empire reporting function with an upgraded version

def xstr(s):
    """Safely cast to a string with a handler for None"""
    if s is None:
        return ''
    return str(s)


# this class MUST be named Plugin
class Plugin(Plugin):
    description = "Generate customized PDF Reports"
    lock = threading.Lock()

    def onLoad(self):
        """ any custom loading behavior - called by init, so any
        behavior you'd normally put in __init__ goes here """

        # you can store data here that will persist until the plugin
        # is unloaded (i.e. Empire closes)
        self.commands = {'do_report': {'Description': 'Generate customized PDF Reports',
                                          'arg': 'the argument required and it''s description'
                                          }
                         }

    def execute(self, dict):
        # This is for parsing commands through the api

        try:
            # esentially switches to parse the proper command to execute
            if dict['command'] == 'do_report':
                results = self.do_report(dict['arguments']['arg'])
            return results
        except:
            return False

    def get_commands(self):
        return self.commands

    def register(self, mainMenu):
        """ any modifications to the mainMenu go here - e.g.
        registering functions to be run by user commands """
        mainMenu.__class__.do_report = self.do_report

    def do_report(self, args):
        'Generate customized PDF Reports'
        # First line used for description

        choice = input("\n [>] Directory to logo: ")
        if choice.lower() != '':
            logoDir = choice
        else:
            logoDir = "./Reports/Templates/empire.png"

        print(helpers.color("[*] Generating Empire Report"))

        # Use this to call MITRE Attack plugin
        software, techniques = Plugin.attack_searcher(self)
        self.EmpireReport(logoDir, software, techniques)

        print(helpers.color("[*] Generating Session Report"))
        self.sessionReport(logoDir)

        print(helpers.color("[*] Generating Credentials Report"))
        self.credentialReport(logoDir)

        print(helpers.color("[*] Generating Masterlog"))
        self.masterLog(logoDir)

        print(helpers.color("[+] All Reports generated"))

    def EmpireReport(self, logoDir, software, techniques):
        self.lock.acquire()

        # Set info from database
        description = software['description']

        # Switch rows and columns of platforms
        platforms = software['x_mitre_platforms']
        platforms = [[platforms[j] for j in range(len(platforms))]]

        # Create list of techniques
        used_techniques = list([])
        for i in range(len(techniques)):
            used_techniques.append('<h3>' + techniques[i]['name'] + '</h3>')
            used_techniques.append(techniques[i]['description'])

        # Load Template

        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./Reports/Templates/empire_report_template.md")

        # Add data to Jinja2 Template
        template_vars = {"logo": logoDir,
                         "description": description,
                         "platforms": tabulate(platforms, tablefmt='html'),
                         "techniques": used_techniques}

        # Generate PDF from html file
        md_out = template.render(template_vars)
        md2pdf("./Reports/Empire_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css', base_url='.')
        self.lock.release()

    def sessionReport(self, logoDir):
        conn = self.database_connect()
        conn = self.get_db_connection()

        self.lock.acquire()

        # Pull agent data from database
        cur = conn.cursor()
        cur.execute('select session_id, hostname, username, checkin_time from agents')
        data = cur.fetchall()

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./Reports/Templates/sessions_template.md")

        # Add headers for table
        sessions = [('SessionID', 'Hostname', 'User Name', 'First Check-in')]
        sessions.extend(data)

        # Add data to Jinja2 Template
        template_vars = {"logo": logoDir,
                         "sessions": tabulate(sessions, tablefmt='html')}

        # Generate PDF from html file
        md_out = template.render(template_vars)
        md2pdf("./Reports/Sessions_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def credentialReport(self, logoDir):
        conn = self.database_connect()
        conn = self.get_db_connection()

        self.lock.acquire()

        # Pull agent data from database
        cur = conn.cursor()
        cur.execute("""
                    SELECT
                        domain
                        ,username
                        ,host
                        ,credtype
                        ,password
                    FROM
                        credentials
                    ORDER BY
                        domain
                        ,credtype
                        ,host
                    """)
        data = cur.fetchall()

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./Reports/Templates/credentials_template.md")

        # Add headers for table
        creds = [('Domain', 'Username', 'Host', 'Cred Type', 'Password')]
        creds.extend(data)

        # Add data to Jinja2 Template
        template_vars = {"logo": logoDir,
                         "creds": tabulate(creds, tablefmt='html')}

        # Generate PDF from html file
        md_out = template.render(template_vars)
        md2pdf("./Reports/Credentials_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def masterLog(self, logoDir):
        conn = self.database_connect()
        conn = self.get_db_connection()

        self.lock.acquire()

        # Pull agent data from database
        cur = conn.cursor()
        cur.execute("""
                                       SELECT
                                           reporting.timestamp,
                                           event_type,
                                           u.username,
                                           substr(reporting.name, pos+1) as agent_name,
                                           a.hostname,
                                           taskID,
                                           t.data as "Task",
                                           r.data as "Results"
                                       FROM
                                       (
                                           SELECT
                                               timestamp,
                                               event_type,
                                               name,
                                               instr(name, '/') as pos,
                                               taskID
                                           FROM reporting
                                           WHERE name LIKE 'agent%'
                                           AND reporting.event_type == 'task' OR reporting.event_type == 'checkin') reporting
                                           LEFT OUTER JOIN taskings t on (reporting.taskID = t.id) AND (agent_name = t.agent)
                                           LEFT OUTER JOIN results r on (reporting.taskID = r.id) AND (agent_name = r.agent)
                                           JOIN agents a on agent_name = a.session_id
                                           LEFT OUTER JOIN users u on t.user_id = u.id
                                       """)

        data = cur.fetchall()

        # Format text as a string and print to new line
        log = ''
        for row in data:
            row = list(row)
            for n in range(len(row)):
                if isinstance(row[n], bytes):
                    row[n] = row[n].decode('UTF-8')
                if type(row[n]) == str:
                    row[n] = str(row[n]).replace('\n', ' <br> ')
            log = log + ' <br> ' + xstr(row[0]) + ' - ' + xstr(row[3]) + ' (' + xstr(row[2]) + ')> ' + xstr(
                row[5]) + xstr(row[6]) + xstr(row[7]) + ' <br> '

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./Reports/Templates/masterlog_template.md")

        # Add data to Jinja2 Template
        template_vars = {"logo": logoDir,
                         "log": log}

        # Generate PDF from html file
        md_out = template.render(template_vars)
        md2pdf("./Reports/Masterlog_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def ModuleReport(self, logoDir, software, techniques):
        conn = self.database_connect()
        conn = self.get_db_connection()

        self.lock.acquire()

        # Pull agent data from database
        cur = conn.cursor()
        cur.execute("""
             SELECT
                 taskings.id,
                 taskings.agent,
                 module_name,
                 software,
                 tt.technique
             FROM
                 taskings
             LEFT OUTER JOIN taskings_techniques tt ON tt.tasking_id = taskings.id
             WHERE taskings.module_name IS NOT NULL
                                """)

        data = cur.fetchall()

        # Format text as a string and print to new line
        module_data = []
        # for i in range(len(data)):
        #    if data[i][2] == data[i-1][2]:
        #        module_data.append(data[i][3])
        #        module_data.append(data[i][4])
        #    else:
        #        module_data.append(data[i][2])

        # Set info from database
        description = software['description']

        # Switch rows and columns of platforms
        platforms = software['x_mitre_platforms']
        platforms = [[platforms[j] for j in range(len(platforms))]]

        # Create list of techniques
        used_techniques = list([])
        for i in range(len(techniques)):
            used_techniques.append('<h3>' + techniques[i]['name'] + '</h3>')
            used_techniques.append(techniques[i]['description'])

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./Reports/Templates/module_report_template.md")

        log = ''
        # Add data to Jinja2 Template
        template_vars = {"logo": logoDir,
                         "log": log}

        # Generate PDF from html file
        md_out = template.render(template_vars)
        md2pdf("./Reports/Module_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def convertHtmlToPdf(self, sourceHtml, outputFilename):
        resultFile = open(outputFilename, "w+b")
        pisaStatus = pisa.CreatePDF(sourceHtml, resultFile)
        resultFile.close()
        return pisaStatus.err

    def get_db_connection(self):
        """
        Returns the
        """
        self.lock.acquire()
        self.conn.row_factory = None
        self.lock.release()
        return self.conn

    def database_connect(self):
        """
        Connect to the default database at ./data/empire.db.
        """
        try:
            # set the database connectiont to autocommit w/ isolation level
            self.conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
            self.conn.text_factory = str
            self.conn.isolation_level = None
            return self.conn

        except Exception:
            print(helpers.color("[!] Could not connect to database"))
            print(helpers.color("[!] Please run database_setup.py"))
            sys.exit()
