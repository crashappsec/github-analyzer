#!/bin/sh

destination=${1:-version.txt}
git describe --tags --long | tee $destination
