#!/usr/bin/env bash

RED=`tput setaf 1`
GREEN=`tput setaf 2`
RESET=`tput sgr0`

if [ -z ${1} ]; then
  echo "${RED}Version not specified. Use make lint version=x.x.x${RESET}"
  exit 1
fi

STATUS=0

if [[ -n $(git status --porcelain) ]]; then
  echo "${RED}Git directory not clean${RESET}"
  STATUS=1
fi

if [ $(git describe --tags) != ${1} ]; then
  echo "${RED}HEAD is not correctly tagged${RESET}"
  STATUS=1
fi

echo "Linting…"
LINT=$(pod lib lint --allow-warnings --sources='git@github.com:AnbionApps/AnbionPods.git,https://github.com/CocoaPods/Specs')
if [ $? -ne 0 ]; then
  echo "${RED}Linting failed:${RESET}"
  echo "${LINT}"
  STATUS=1
fi

if ! $(echo ${LINT} | grep -qF "(${1})")
then
  echo "${RED}Version in podspec incorrect${RESET}"
  STATUS=1
fi

echo ""
if [ $STATUS == 0 ]; then
  echo "${GREEN}All good!${RESET}"
else
  echo "${RED}There were errors${RESET}"
fi

exit $STATUS
