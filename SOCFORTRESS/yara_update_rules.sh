#!/usr/bin/bash
# Yara rules - Compiled file creation
#
#------------------------- Aadjust IFS to read files -------------------------#
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Folder where Yara rules (files) will be placed -------------------------#
git_repo_folder="/usr/local/signature-base"
yara_file_extenstions=( ".yar" )
yara_rules_list="/usr/local/signature-base/yara_rules_list.yar"

#------------------------- Main workflow --------------------------#

# Update Github Repo
cd $git_repo_folder
/bin/git pull https://github.com/Neo23x0/signature-base.git

# Remove .yar files not compatible with standard Yara package
/bin/rm $git_repo_folder/yara/generic_anomalies.yar $git_repo_folder/yara/general_cloaking.yar $git_repo_folder/yara/thor_inverse_matches.yar $git_repo_folder/yara/yara_mixed_ext_vars.yar $git_repo_folder/yara/apt_cobaltstrike.yar $git_repo_folder/yara/apt_tetris.yar $git_repo_folder/yara/gen_susp_js_obfuscatorio.yar

# Create File with rules to be compiled
if [ ! -f $yara_rules_list ]
then
    /usr/bin/touch $yara_rules_list
else /bin/rm $yara_rules_list
fi
for e in "${yara_file_extenstions[@]}"
do
  for f1 in $( find $git_repo_folder/yara -type f | grep -F $e ); do
    echo "include \"""$f1"\""" >> $yara_rules_list
  done
done
# Compile Yara Rules
/opt/yara-4.1.3/yarac $yara_rules_list /usr/local/signature-base/yara_base_ruleset_compiled.yar
IFS=$SAVEIFS
exit 1;
