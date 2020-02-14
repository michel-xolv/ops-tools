#!/bin/bash
# Creates or updates Config policy for an AWS Account
# Environment: Linux BASH, AWS package with .aws configuration files set up
# Some actions below expect AWS accounts to be defined in .aws/config
# 
#Usage: $0 <type> <value> where type is 'a'ccount, 's'ns Topic, 'b'ucket 'm'ail
# 'a' is mandatory and needs be one of the conventional names in ~/.aws
# 'm' is mandatory and is the e-mail address or alias to which SNS will be sent
# 's' for the name of the DND Topic to use; defaults to 'sns-aws-config'
# 'b' is S3 bucket to use; defaults to 'xolv.out.aws.config.$ACCOUNT'
#  ...which means we DO NOT expect to use the same bucket for all accounts.
# Parameters and defaults
BUCKET="xolv.out.aws.config"
PREFIX="awsconfig"
SNSTOPIC="awsconfig-queue"
SNSTO='mbouckaert@xolv.org'

#  The value of "NUMACCT" is derived either from the default assumed identity 
# for the profile in use. If the profile name given on the command line is not
#  found, an error is returned
# Files will be created in a subdirectory of /tmp and removed at end of run
SUBDIR="/tmp/$$"
mkdir "$SUBDIR"
while getopts ":a:s:b:" OPTION; do
 echo "TRACE: $OPTION"
   case "$OPTION" in
   a) # Account to use
      if [ "x$OPTARG" != x ]; then ACCOUNT=$OPTARG ;  fi
      ;;
   s) # Name of the SNS Topic to use
      if [ "x$OPTARG" != x ]; then SNSTOPIC=$OPTARG ; fi
      ;;
   b) # Name of the Bucket to use 
      if [ "x$OPTARG" != x ]; then BUCKET=$OPTARG ;   fi
      ;;
   m) # e-mail address to send SNS to
      if [ "x$OPTARG" != x ]; then SNSTO=$OPTARG ;    fi
      ;;
   \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
   esac
done

# Lower case, no hyphens ar spaces for S3
BUCKET=$( echo "$BUCKET" | tr '[:upper:] ' '[:lower].' )

echo "TRACE2: $ACCOUNT"
NUMACCT=$(aws sts get-caller-identity --query "Account"                        \
	  --profile $ACCOUNT | tr -d '"')

LOWACCT=$( echo "$ACCOUNT" | tr '[:upper:]-' '[:lower:].')
BUCKET="$BUCKET-$NUMACCT"
LOGBCKT="xolv.log.aws.comfig.$NUMACCT"
PROFILE=" --profile $ACCOUNT"

# Note that this is actually a SHORTCUT.  It means that we will use separate
# Buckets for separate Accounts.  It is possible to have awsConfig push all
# reports to the same Bucket; but it is unlikely I have proper permissions
# for Production accounts (if I had I could cause data leaks unless I have
# access to the approprioate data dictionaries).
# You can find instructions to provide $BUCKET with proper permissions here:
# https://aws.amazon.com/premiumsupport/knowledge-center/\
#	s3-cross-account-upload-access/

# Check the account is known to the local .aws 
case $ACCOUNT in
   ESBA-OPS-DEV |ESBA-OPS-PROD |ESBA-ENG-DEV |ESBA-ENG-PROD |ESBA-ES-HAWAII)
   ACCT=$( aws sts get-caller-identity --query "Account" --profile $ACCOUNT )
      ERC=$?
      if [ $ERC != 0 ]; then
              echo "could not get account number for '$ACCOUNT'; abortng" >&2
              exit $ERC
              fi
   ;;
   *) echo "Invalid option '$ACCOUNT'"; exit 2 ;;
esac

# With all run cariables set, we can generate required JSON parameter files
# =============================================================================

# Build ACL for configuration bucket logs
cat >$SUBDIR/logBucketAcl.json <<log.bucket-acl-template
{
  "LoggingEnabled": {
    "TargetBucket": "$LOGBCKT",
    "TargetPrefix": "$PREFIX/",
    "TargetGrants": [
      {
        "Grantee": {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
         },
        "Permission": "WRITE"
      },
      {
        "Grantee": {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
         },
        "Permission": "READ_ACP"
      }
    ]
  }
}
log.bucket-acl-template


# Build Trust Policy for AWS Config
cat > $SUBDIR/trustPol.json <<DefineTrustPolicyHere
{
  "Version": "2012−10−17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
DefineTrustPolicyHere

# To allow all source lines to fit in 80 characters
S3RESOURCE="arn:aws:s3:::$BUCKET/$PREFIX/AWSLogs/$NUMACCT/Config/*"
cat > $SUBDIR/GrantConfigAccessS3.json  <<DefineGrantAccessForConfigToS3
{ 
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::$BUCKET"
    },
    {
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "config.amazonaws.com"
        ]
      },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::$BUCKET"
    },
    {
      "Sid": " AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"    
        ]
      },
      "Action": "s3:PutObject",
      "Resource": "$S3RESOURCE",
      "Condition": { 
        "StringEquals": { 
          "s3:x-amz-acl": "bucket-owner-full-control" 
        }
      }
    }
  ]
}   
DefineGrantAccessForConfigToS3


# Build supplemental Policy to add to any existing Bucket Policy,
# to grant AWSConfig permission to record the S3 bucket (?)
AWSCONFIGROLE="AWSServiceRoleForConfig"
cat > $SUBDIR/PolicyS3.json <<DefineAdditionalBucketPolicyHere
{
    "Sid": "AWSConfig_ReadConfiguration_Access",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::$NUMACCT:role/$AWSCONFIGROLE"},
    "Action": [
        "s3:GetAccelerateConfiguration",
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketNotification",
        "s3:GetBucketPolicy",
        "s3:GetBucketRequestPayment",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration"
    ],
    "Resource": "arn:aws:s3:::$BUCKET"
}
DefineAdditionalBucketPolicyHere


# Build IAM Role Policy for S3 Bucket 
#  (use only for IAM Role, not for Service-linked-role )
# Derive proper ARN from Bucket name whether it exists or not
# "Resource": ["arn:aws:s3::: myBucketName/prefix/AWSLogs/myAccountID/*"],
###
cat > $SUBDIR/RoleS3.json <<DefineRolePolicyForS3Here
{
  "Version": "2012−10−17",
  "Statement": 
   [
     {
       "Effect": "Allow",
       "Action": ["s3:PutObject"],
       "Resource": ["arn:aws:s3:::$BUCKET/$PREFIX/AWSLogs/$NUMACCT/*"],,
       "Condition":
        {
          "StringLike":
            {
              "s3:x−amz−acl": "bucket−owner−full−control"
            }
        }
     },
     {
       "Effect": "Allow",
       "Action": ["s3:GetBucketAcl"],
       "Resource": "arn:aws:s3:::$BUCKET/* "
     }
  ]
}
DefineRolePolicyForS3Here


# Derive proper ARN from SNS Topic name whether it exists or not
# Build IAM Role Policy for SNS Topic to be used by AWS Config
cat > $SUBDIR/IAMPolicyForSNS.json <<DefineRolePolicyForSNSTopicHere
{
  "Version": "2012−10−17",
  "Statement":
   [
     {
      "Sid": "AWSConfigSNSPolicy",
      "Effect":"Allow",
      "Principal": {
        "AWS": "[configRoleArn]"
      },
      "Action":"sns:Publish",
      "Resource":"arn:aws:sns:$REGION:$NUMACCT:$SNSTOPIC"
     }
   ]
}
DefineRolePolicyForSNSTopicHere


# JSON to define an aggregator for this account.  See pages 229-230 of 
#   the "AWS Config Developer Guide" for variants e.g. multi-account
cat > $SUBDIR/aggregator.1account.json <<DefinitionAggregatorSingleAccount
[
  {
    "AccountIds": [ $NUMACCT ],
    "AllAwsRegions": true,
  }
]
DefinitionAggregatorSingleAccount

# Rable of AWS Regions (to enable Aggregators on)
# The "ap-east-1', 'eu-north-1', 'me-south-1'  and 'ap-northeast-3' regions
#    are not supported as of 2020/2 for configservice thus not listed below.
cat > $SUBDIR/aws.regions <<AWS.region.codes.definition
ap-northeast-1
ap-northeast-2
ap-south-1
ap-southeast-1
ap-southeast-2
ca-central-1
eu-central-1
eu-west-1
eu-west-2
eu-west-3
sa-east-1
us-east-1
us-east-2
us-west-1
us-west-2
AWS.region.codes.definition

# −−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−
# JSON Files set up 
# trustpol.json			-  Allows Config to assume a role in this Acct
# GrantConfigAccessS3.json	-  Grants access to it by config.amazonaws.com 
# PolicyS3.json			-  Supplemental policy if Config reports on S3
# RoleS3.json			-  Allows S3 to write to its reporting bucket
# IAMPolicyForSNS.json

# Trace capability: For each aws command, output a command number
# followed by the command's result (on STOUT or STDERR) if possible
##################)#####################################
function _tell {
   if $TRACE;  then T="$1"; echo "$T='${!T}'"; fi }

echo -e "\nResults this far:\n--------------------"
ls -1 $SUBDIR
echo -e "\n...et ...\n"
_tell ACCOUNT
_tell BUCKET
_tell LOGBCKT
_tell LOWACCT
_tell NUMACCT
_tell PREFIX
_tell PROFILE
_tell SNSTOPIC
_tell SUBDIR
exit
################$#######################################
# If we go this route, Config will assume the Role of the entity executing 
# this Script (or what is what it sounds like: trusdtpol.json apparently 
# gives permission to the currently active Role since there is no Role in 
# that JSON).
# It is safer to use a Service-linked Role since that is independent from the 
# currently active user, and to edit the Service-linked Role definition to 
# allow only such Permissions as absolutely needed.  See (note backslash!)
#    https://docs.aws.amazon.com/\
#        config/latest/developerguide/using-service-linked-roles.html
# for that

# -----------------------------------------------------------------------------
# Create service-linked role for Config. This is the only one for awsconfig,
# it can be edited using IAM but this is a singleton. 
# No custom-suffix or edits for this Role either.
# See both "aws iam" and "aws configservice".
aws iam create-service-linked-role --aws-service-name config.amazonaws.com     \
	--description "Account-local-limited-aws-config" $PROFILE
# Note the detailed information in https://docs.aws.amazon.com/IAM/latest/\
#	UserGuide/using-service-linked-roles.html#edit-service-linked-role
# refarding deletimg service-linked roles.  Because of the variety of failure
# reasons when attempting deletes, this should rather be done from Console, 
# not CLI or API
# -----------------------------------------------------------------------------
# Create Trust Policy so AWSConfig can reach in

# −−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−
# Does bucket $BUCKET already exist? If so abort (for now)
if [ $(aws s3api list-buckets --query 'Buckets[].Name[]' |awk -v b="$BUCKET"   \
	'BEGIN{FS=":";count=0};
	 $2!=""{if( b == $2) count++};
	 END{print count};') -gt 0 ]; then
   echo "BUcket '$BUCKET' already exists.  Currently, we stop tnd review." >&2
   exit 3
fi
# Create bucket "$BUCKET" and grant proper accesses to serrvice-based-role 
# See: https://docs.aws.amazon.com/config/latest/developerguide/\
#   s3-bucket-policy.html#required-permissions-using-servicelinkedrole
# and: http:.../cli/latest/reference/s3api/put-bucket-policy.html
# and: https://linuxacademy.com/guide/\
#   21775-how-to-pass-file-content-as-parameter-to-aws-cli/
# plus: https://docs.aws.amazon.com/config/latest/developerguide/\
#   iamrole-permissions.html, specifically the section on troubleshooting.
# Policy text in  $SUBDIR/PolicyS3.json in this script

aws s3api create-bucket --bucket "$BUCKET"                                     \
       	--create-bucket-configuration '{ "LocationConstraint": "us-west-2" }'  \
	--region us-west-2 --acl private  $PROFILE &&                          \
   aws s3api put-bucket-policy --bucket "$BUCKET"                              \
      --policy file://$SUBDIR/GrantConfigAccessS3.json $PROFILE
ERC=$?

if [ $ERC != 0 ]; then
   echo "Couldnt create bucket '$BUCKET' with proper ACL. Stop for review." >&2
   exit 3
fi

if [ $(aws s3api list-buckets --query 'Buckets[].Name[]' $PROFILE              \
	| awk -F: -v b="$LOGBCKT"                                             \
	'BEGIN{ct=0}; $2!=""{if( b == $2) ct++}; END{print ct};') .eq 0 ]
then # Does not exist yet
   aws s3api create-bucket                                                     \
      --create-bucket-configuration '{ "LocationConstraint": "us-west-2" }'    \
      --bucket "$LOGBCKT" --region us-west-2 --acl private  $PROFILE &&        \
   aws s3api put-bucket-acl --bucket "$LOGBCKT"                                \
      --grant-write URI=http://acs.amazonaws.com/groups/s3/LogDelivery         \
      --grant-read-acp URI=http://acs.amazonaws.com/groups/s3/LogDelivery      \
      $PROFILE
   ERC=$?

   if [ $ERC != 0 ]; then
     echo "Couldnt create bucket '$LOGBCKT' with proper ACL. Check." >&2       \
     exit 3
   fi
fi

aws s3api put-bucket-logging --bucket "$LOGBCKT"                               \
	--bucket-logging-status file://$SUBDIR/logBucketAcl.json $PROFILE
ERC=$?

if [ $ERC != 0 ]; then
  echo "Couldnt setting logging for '$LOGBCKT'. Check." >&2       \
  exit 3
fi

# Check that SNS Topic does (not) exist and create if not there
#
if [ $(aws sns list-topics --query 'Topics[].TopicsArn[]' $PROFILE             \
	| awk -F: -v ct=0 -v b='$SNSTOPIC'                                           \
	'$6!=""{if( b==substr($6,1,index($6,"\"")-1)) ct++};
         END{print ct}' )  .eq 0 ]
then # Does not exist yet
   aws sns create-topic --name "$SNSTOPIC"
fi

# How to define and use aggregators for single account / multiregion
 aws configservice put-configuration-aggregator                                \
   --configuration-aggregator-name "ESBA-OPS-DEV-allRegions"                   \
   --account-aggregation-sources file://$SUBDIR/aggregator.1account.json

# Add authorization for aggregator in each region 
#   (see note in the definition of Regions)
cat $SUBDIR.aws.regions | while read REGION; do
   aws configservice put-aggregation-authorization                             \
	   --authorized-account-id $NUMACCT                                    \
	   --authorized-aws-region $REGION
done
