# CodePipeline Poisoning Tester

The CodePipeline Poisoning Tester (CPPT in advance) is a tool composed by a Python script and an AWS serverless infrastructure that will help verify wether AWS developers could potentially perform a privilege escalation attempt to retrieve secrets and data from the CI/CD pipeline and the production environment. More information about this tool and the risk it attempts to help identify is described in the article available [here](addLinkToArticle).

***Important:*** At this moment, the CPPT tool only supports CodePipeline executions that target an EC2 or On-premise deployment.

## Setup

1. Create a user (test-user in advance) with the same access right as the current developers.
2. Create programmatic access credentials for the test-user and keep the Access Key Id and Secret Access Key to be used with the CPPT Script.
3. Use the provided CloudFormation template to deploy the API infrastrucuture used by CPPT [codePipelinePoisoningTesterAPI.yaml](./codePipelinePoisoningTesterAPI.yaml).
4. Check the CloudFormation template Output values and use them with the CPPT script.
5. Get the name of the CodePipeline project to be tested and use it with the CPPT script.

## Usage

The script requires has dependencies that are listed in the requirements.txt file, which can be used as input for pip3. The script supports common CLI command flags and parameters, so you can use the following to print out the help information.

```
../codepipeline-poisoning-tester
$ python3 ./codePipelinePoisoningTester.py --help
usage: codePipelinePoisoningTester.py [-h] [-r [eu-west-1]] [-t [120]]
                                      [-o [file.logs]] [-m [1]]
                                      Pipeline_Name Access_Key_Id
                                      Secret_Access_Key CPPT_API_URL
                                      CPPT_API_Key

Poison and monitor the selected CodePipeline pipeline for testing purposes.

positional arguments:
  Pipeline_Name         The name of the pipeline to be poisoned
  Access_Key_Id         The AWS ACCESS KEY ID used to authenticate with AWS
  Secret_Access_Key     The AWS SECRET ACCESS KEY used to authenticate with
                        AWS
  CPPT_API_URL          The URL of the API Gateway for CodePipeline Poisoning
                        Tester (CPPT)
  CPPT_API_Key          The API Key of the API Gateway for CodePipeline
                        Poisoning Tester (CPPT)

optional arguments:
  -h, --help            show this help message and exit
  -r [eu-west-1], --AWS-REGION [eu-west-1]
                        AWS region used to create the clients (default: eu-
                        west-1)
  -t [120], --TIMEOUT-MONITOR [120]
                        Timeout for monitoring task in seconds (default: 120)
  -o [file.logs], --OUTPUT-FILE [file.logs]
                        Ammount of executions to infect (default:
                        cpptOutput.logs)
  -m [1], --MAX-EXECUTIONS [1]
                        Ammount of executions to infect (default: 1)

```

An example of how to use the CPPT script:

```
../codepipeline-poisoning-tester
$ python3 ./codePipelinePoisoningTester.py MyPipeline AKIA***ABC IgJa***6Fo \
"https://ym2thial00.execute-api.eu-west-1.amazonaws.com/ccptStage/cpptRoute" "cpptApiKey"
```

## Context

The CPPT tool infrastructure design is shown in the image below (denoted with red colours), together with other AWS components used in CI/CD pipelines within AWS, such as CodePipeline, CodeBuild, S3, etc. 

![CPPT infrastructure design](./resources/AWS_CICD_Analysis_Pages_CPPT-Main.png)

The CCPT tool works as explained in the following steps, which also represent the common CI/CD pipeline steps: Source, Build, Others, and Deploy. The following images contain black and gray arrows that denote the common CI/CD pipeline steps and red arrows that denote CPPT functionality.

### **1. Source phase**

Once a pipeline execution is started via CodePipeline, the process will start with the **Source phase**, as represented in the image below. When you start the CPPT script in the local device, the CCPT script will start querying CodePipeline in order to gather information about the running pipeline executions (You can start the CPPT script before the pipeline execution starts).

![Source phase](./resources/AWS_CICD_Analysis_Pages_CPPT-Source.png)

### **2. Build phase**

The CPPT script will continue querying CodePipeline to gather information regarding the random location in which CodeBuild will store the output artifacts for this pipeline execution. Once the output artifact is known, the CPPT script will request CodeBuild to start a new build with the properties listed below. In addition, once the start build is successful, the CPPT script will POST the information to the CPPT API.

CPPT script start build properties:
        
- buildspecOverride parameter: 
  - A CPPT crafted buildspec that will poison the output artifact.
  - No need to worry, this tool only injects two commands to be executed by the container and the server:
    - Creates an empty local file.
    - Sends a POST request to the CPPT API.
- arifactsOverride parameter:
  - The output artifact location being the same as the one received by querying CodePipeline.
  - This will override the legitimate artifact created within the pipeline execution.

![Build phase](./resources/AWS_CICD_Analysis_Pages_CPPT-Build.png)

### **3. Others phase**

While the pipeline execution is performing other tasks, such as SAST analysis and/or a manual approval, the build started by the CPPT script will be performed.

As shown in the diagram below, the container used to build the artifact will follow the CPPT crafted buildspec which contacts the CPPT API to update the value for the poisoned artifact package. The success of this action also means that users with the same access level as the test-user can execute arbitrary commands within the container. Therefore, the AWS deveoper could gain access to protected resources that are used within the container, such as code signing keys and production configuration files.

In addition, the CPPT crafted buildspec will create and add to the posioned artifact a file called *CPPTWasHere.container*. The existence of this file within the artifact file also demonstrates that arbitrary code can be executed within the build container. This can be useful in case it is not wanted to use the CPPT API, or the container lacks access to the internet.

The CPPT crafted buildspec will also poison the output artifact package by adding a CPPT crafted appspec file and script. This poisoned artifact package will replace the original one created by the legitimate build run by the pipeline execution. This appspec file and script will follow a similar approach as the CPPT crafted buildspec: 
- Contact the CPPT API.
- Create a file.

In the background, the CPPT script will start querying the CPPT API to show the user a table to monitor the status of the poisoned artifacts.

![Others phase](./resources/AWS_CICD_Analysis_Pages_CPPT-Others.png)

### **4. Deploy phase**

Last, CodePipeline will request CodeDeploy to perform its task and the deployment will execute as usual. CodeDeploy will contact the target CodeDeploy agents and provide them the information about the new artifact.However, if the CPPT script triggered was finished in time, the package downloaded by the CodeDeploy agent will be the poisoned package artifact, as shown in the image below.

As a result, the CodeDeploy agent will run the CPPT craftet appspec file and script. This will send a POST request to the CPPT API and create a local file named *CPPTWasHere.server* in the root directory of the server. The success of this action also means that users with the same access level as the test-user could potentially execute arbitrary commands within the server. Therefore, developers could gain access to protected resources that are used within the server, such as production data and secrets, execute root level commands, and access other services that may be only accessible via the deploy machine.

In the background, the CPPT script will continue querying the CPPT API to show the user a table to monitor the status of the poisoned artifacts. The status of the different attempts can always be checked directly in the DynamoDB table created for the CPPT API via CloudFormation.

![Deploy phase](./resources/AWS_CICD_Analysis_Pages_CPPT-Deploy.png)

## Disclaimer of Warranties and Limitation of Liability

The contents of this repository are offered on an as-is and as-available basis and the authors make no representations or warranties of any kind concerning the contents, whether express, implied, statutory, or other. This includes, without limitation, warranties of title, merchantability, fitness for a particular purpose, non-infringement, absence of latent or other defects, accuracy, or the presence or absence of errors, whether or not known or discoverable.

To the extent possible, in no event will the authors be liable on any legal theory (including, without limitation, negligence) or otherwise for any direct, special, indirect, incidental, consequential, punitive, exemplary, or other losses, costs, expenses, or damages arising out of the use of the contents, even if the the authors have been advised of the possibility of such losses, costs, expenses, or damages.

The disclaimer of warranties and limitation of liability provided above shall be interpreted in a manner that, to the extent possible, most closely approximates an absolute disclaimer and waiver of all liability.
