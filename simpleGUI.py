import PySimpleGUI as sg
import os
import subprocess
from virtualenv import cli_run

sg.theme('DarkAmber')   # Add a touch of color

# All the stuff inside your window.
layout = [  [sg.Text('Enter IP Address and Port Number', font='Courier 10')],
            [sg.Text('IP Address', font='Courier 10'), sg.InputText(default_text='127.0.0.1', size=(16,None), font='Courier 10')],
            [sg.Text('Port Number', font='Courier 10'), sg.InputText(default_text='9999', size=(15,None), font='Courier 10')],
            [sg.Button('Install Requirements (Ubuntu)', font='Courier 9')],
            [sg.Button('Host', font='Courier 9'), sg.Button('View', font='Courier 9'), sg.Button('Exit', font='Courier 9')] ]

# Create the Window
window = sg.Window('Cryptography Project 2', layout)


# Event Loop to process "events" and get the "values" of the inputs
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit': # if user closes window or clicks cancel
        break
    if event == 'Install Requirements (Ubuntu)':
        cli_run(["venv"])
#        pip_list = subprocess.run(["pip3", "list"])
        install_req = subprocess.run(["venv/bin/pip3", "install", "-r", "secproject_basic_stream_app/requirements_ubuntu.txt"])
    if event == 'Host':
#        print('venv/bin/python3 streaming_multi_client_server_with_select.py -i', values[0], '-p', values[1])
        host_stream = subprocess.run(["venv/bin/python3", "secproject_basic_stream_app/streaming_multi_client_server_with_select.py", "-i", values[0], "-p", values[1]])
    if event == 'View':
#        print('venv/bin/python3 streaming_client.py -i', values[0], '-p', values[1])
        view_stream = subprocess.run(["venv/bin/python3", "secproject_basic_stream_app/streaming_client.py", "-i", values[0], "-p", values[1]])



window.close()
