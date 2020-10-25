"""Overwrites the Empire reporting function with an upgraded version"""
from __future__ import print_function

from lib.common.plugins import Plugin
from jinja2 import Environment, FileSystemLoader
from tabulate import tabulate
from .attack import Plugin
from md2pdf.core import md2pdf
import lib.common.helpers as helpers
import lib.common.modules as modules
import threading
import sqlite3
import sys

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
        self.commands = {'do_report': {'Description': 'Generate customized PDF Reports',
                                       'arg': '[logo directory]'
                                       }
                         }

    def execute(self, command_list):
        try:
            if command_list['command'] == 'do_report':
                results = self.do_report(command_list['arguments']['arg'])
            return results
        except:
            return False

    def get_commands(self):
        return self.commands

    def register(self, mainMenu):
        """ any modifications to the mainMenu go here - e.g.
        registering functions to be run by user commands """
        mainMenu.__class__.do_report = self.do_report

    def do_report(self, *args):
        'Generate customized PDF Reports'
        # First line used for description
        if args[0] == '':
            print(helpers.color("[!] report [logo directory]"))
            print(helpers.color("[*] Using default Empire logo"))
            logo_dir = "./Reports/Templates/empire.png"
        else:
            logo_dir = args[0]

        print(helpers.color("[*] Generating Empire Report"))

        # Pull techniques and software used with Empire
        software, techniques = Plugin.attack_searcher(self)
        self.EmpireReport(logo_dir, software, techniques)

        print(helpers.color("[*] Generating Session Report"))
        self.sessionReport(logo_dir)

        print(helpers.color("[*] Generating Credentials Report"))
        self.credentialReport(logo_dir)

        print(helpers.color("[*] Generating Master Log"))
        self.masterLog(logo_dir)

        # Pull all techniques from MITRE database
        # TODO: Pull all software for module report
        techniques = Plugin.all_attacks(self)
        print(helpers.color("[*] Generating Module Report"))
        self.ModuleReport(logo_dir, software, techniques)

        print(helpers.color("[+] All Reports generated"))

    def shutdown(self):
        """if the plugin spawns a process provide a shutdown method for when Empire exits else leave it as pass"""
        return

    def EmpireReport(self, logo_dir, software, techniques):
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
        template_vars = {"logo": logo_dir,
                         "description": description,
                         "platforms": tabulate(platforms, tablefmt='html'),
                         "techniques": used_techniques}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./Reports/Markdown/Empire_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./Reports/Empire_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def sessionReport(self, logo_dir):
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
        template_vars = {"logo": logo_dir,
                         "sessions": tabulate(sessions, tablefmt='html')}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./Reports/Markdown/Sessions_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD files)
        md2pdf("./Reports/Sessions_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def credentialReport(self, logo_dir):
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
        template_vars = {"logo": logo_dir,
                         "creds": tabulate(creds, tablefmt='html')}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./Reports/Markdown/Credentials_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./Reports/Credentials_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def masterLog(self, logo_dir):
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
        template_vars = {"logo": logo_dir,
                         "log": log}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./Reports/Markdown/Masterlog_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./Reports/Masterlog_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

    def ModuleReport(self, logo_dir, software, techniques):
        conn = self.database_connect()
        conn = self.get_db_connection()
        self.lock.acquire()

        # Pull agent data from database
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT
            module_name
            FROM
            taskings
            WHERE taskings.module_name IS NOT NULL
                                """)

        data = cur.fetchall()

        ttp = list([])
        module_name = list([])
        for module_directory in data:
            ttp.append(self.mainMenu.modules.modules[module_directory[0]].info['Techniques'])
            module_name.append(self.mainMenu.modules.modules[module_directory[0]].info['Name'])

        # Create list of techniques
        used_techniques = list([])
        for ttp_list in ttp:
            for ttp_name in ttp_list:
                for i in range(len(techniques)):
                    if ttp_name in techniques[i]._inner['external_references'][0]._inner['external_id']:
                        try:
                            used_techniques.append('<h3>' + techniques[i]['name'] + '</h3>')
                            used_techniques.append(
                                '**Empire Modules Used:** ' + module_name[ttp.index(ttp_list)] + '<br><br>')
                            used_techniques.append(techniques[i]._inner['description'])
                        except:
                            pass

        # Load Template
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template("./Reports/Templates/module_report_template.md")

        log = ''
        # Add data to Jinja2 Template
        template_vars = {"logo": logo_dir,
                         "techniques": used_techniques}

        # Save Markdown to file, if it requires editing
        md_out = template.render(template_vars)
        file = open('./Reports/Markdown/Module_Report.md', 'w')
        file.write(md_out)
        file.close()

        # Generate PDF from MD file
        md2pdf("./Reports/Module_Report.pdf", md_content=md_out, css_file_path='./Reports/Templates/style.css',
               base_url='.')
        self.lock.release()

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
            # set the database connection to autocommit w/ isolation level
            self.conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
            self.conn.text_factory = str
            self.conn.isolation_level = None
            return self.conn

        except Exception:
            print(helpers.color("[!] Could not connect to database"))
            print(helpers.color("[!] Please run database_setup.py"))
            sys.exit()
