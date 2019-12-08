#! /usr/bin/env python3
# pylint: disable=E1101

'''o365 Audit Log Extractor

Audit logs exported from the Office365 Protection Center leave much to be desired.  This script 

This script accepts comma separated value files (.csv) or a directory of CSV files as input.

Author: Ian Day
Initial Release: December 8 2019 Version 1.0
'''

import argparse
import csv
import datetime
import json
import logging
import pathlib
import sys
from collections import defaultdict

VERSION = '1.0'
NAME = 'o365 Audit Log Extractor'


if __name__=='__main__':

    # parse command line arguments
    parser = argparse.ArgumentParser(description='o365 Audit Log Extractor')
    parser.add_argument(help = 'File/Directory to process', type=str, dest='input' )
    parser.add_argument('-o', '--output', help='Output directory, defaults to current directory', type=pathlib.Path, default=pathlib.Path.cwd(), dest='output')
    parser.add_argument('-p', '--prefix', help='Prefix for output files, defaults to o365AuditLog', type=str, default='o365AuditLog', dest='prefix')
    parser.add_argument('-f', '--format', help='Output file format, defaults to csv', type=str, choices=['csv', 'json' ], default='csv', dest='format')
    outputOptions = parser.add_mutually_exclusive_group(required=True)
    outputOptions.add_argument('-w', '--workload', help='Generate individual output files per workload', action='store_true', dest='workload')
    outputOptions.add_argument('-c', '--combined', help='Generate one output file', action='store_true', dest='combined')
    parser.add_argument('-v', '--verbose', help='Enable debug logging', action='store_true', dest='verbose')
    parser.add_argument('--version', action='version',version='{0} {1}'.format(NAME, VERSION))
    args = parser.parse_args()

            
    # configure logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    # log to screen
    ch = logging.StreamHandler()
    # log to file
    fh = logging.FileHandler('{0}_{1}.log'.format( NAME.replace(' ', '_'), datetime.datetime.now().strftime('%Y%m%d-%H%M%S')))
    if args.verbose:
        fh.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        fh.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    # format log output
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)


    logger.info('{0} v{1} Started'.format(NAME, VERSION))

    # determine input type
    logger.debug('Checking input: {0}'.format(args.input))    
    
    # check input
    try:
        input_object = pathlib.Path(args.input)
    except:
        logger.error('Invalid input path specified, terminating script')
        sys.exit(1)

    # check output, attempt to create
    try:
        args.output.mkdir(parents=True,exist_ok=True)
    except :
        logger.error('Invalid output path or permissions error, terminating script')
        logger.error(sys.exc_info()[0])
        sys.exit(1)


    if not input_object.is_file() and not input_object.is_dir():
        logger.error('Invalid input path specified, terminating script')
        sys.exit(1)
    
    else:
        # determiine list of files to process, expanding file path before adding to list
        if input_object.is_file():
            logger.debug('Input detected as file')
            filesToProcess=[input_object.resolve()]
        else:
            logger.debug('Input detected as directory')
            filesToProcess=list(map(lambda x: x.resolve(), input_object.iterdir()))

        #dicts to hold record field names and parsed results
        fieldNames = defaultdict(set)
        results = defaultdict(list)

        # process files
        for entry in filesToProcess:
            try:
                logger.info('Processing file: {}'.format(entry))
                with open(entry, 'r', encoding='latin-1') as inFile:
                    counter = 0
                    # loop through input file
                    dictReader = csv.DictReader(inFile)
                    for line in dictReader:
                        try:
                            # transform auditData to dictionary
                            record = json.loads(line['AuditData'])
                            
                            # remove random linebreaks in field values
                            # its a feature, not a bug
                            for field in record:
                                if isinstance(record[field], str):
                                    record[field] = record[field].strip()
                            
                            # get list of fields in auditData
                            recordFields = list(record.keys())
                            
                            # events of the same Workload can have different fields
                            # create a union to ensure fields not seen yet are included in final output
                            fieldNames[record['Workload']] = set().union(recordFields, fieldNames[record['Workload']])

                            # add record to results and update record count
                            results[record['Workload']].append(record)
                            counter += 1
                        
                        except Exception as e:
                            logger.error('unable to parse line {0} in file {1}'.format(counter, entry))
                            logger.error('error message: {}'.format(e.message))
                
                # log record count per workload
                logger.info('Processing complete, {} records found'.format(counter))

            except Exception as e:
                logger.error('error processing file: {}'.format(entry))
                logger.error('error message: {}'.format(e.message)) 
        
        # sort and output records
        logger.info('Beginning export')

        # export one file with all workloads
        if args.combined:
            
            if args.format == 'csv':
                # combine field names into one list
                combinedFieldNames = set()
                for workload in fieldNames:
                    combinedFieldNames = set().union(combinedFieldNames, fieldNames[workload])

                # generate output path and open file
                fileName = '{}-combinedRecords.csv'.format(args.prefix)
                output_obj = pathlib.Path(args.output.resolve(), fileName)
                logger.debug('Path: {}'.format(output_obj))
                with open(output_obj, 'w') as outFile:
                
                    # create dictionary writer and write headers
                    dictWriter=csv.DictWriter(outFile, fieldnames=combinedFieldNames, lineterminator='\n')
                    dictWriter.writeheader()

                    for workload in results:
                        logger.info('Sorting and exporting {0} {1} records to CSV file'.format(len(results[workload]), workload))
                        # sort records based on timestamp in CreationTime field
                        results[workload] = sorted(results[workload], key=lambda t: t['CreationTime'])
                        # write results to file
                        dictWriter.writerows(results[workload])
            
            if args.format == 'json':
                logger.info('Exporting records to JSON file')
                #combine workloads into one list for export
                allResults = []
                for workload in results:
                    for entry in results[workload]:
                        allResults.append(entry)

                # generate output path and open file
                fileName = '{}-combinedRecords.json'.format(args.prefix)
                output_obj = pathlib.Path(args.output.resolve(), fileName)
                logger.debug('Path: {}'.format(output_obj))
                with open(output_obj, 'w') as outFile:
                    json.dump(allResults, outFile)     

        # export one file per workload   
        if args.workload:

            if args.format == 'csv':
                for workload in results:
                    logger.info('Sorting and exporting {0} {1} records to CSV file'.format(len(results[workload]), workload))
                    
                    # sort records based on timestamp in CreationTime field
                    results[workload] = sorted(results[workload], key=lambda t: t['CreationTime'])
                    
                    # write to file
                    fileName = '{0}-{1}.csv'.format(args.prefix, workload)
                    output_obj = pathlib.Path(args.output.resolve(), fileName)
                    with open(output_obj, 'w') as outFile:
                        logger.debug('Path: {}'.format(output_obj))
                        dictWriter=csv.DictWriter(outFile, fieldnames=fieldNames[workload], lineterminator='\n')
                        dictWriter.writeheader()
                        dictWriter.writerows(results[workload])
            
            if args.format == 'json':
                for workload in results:
                    logger.info('Sorting and exporting {0} {1} records to JSON file'.format(len(results[workload]), workload))
                    
                    # sort records based on timestamp in CreationTime field
                    results[workload] = sorted(results[workload], key=lambda t: t['CreationTime'])
                    
                    # write to file
                    fileName = '{0}-{1}.json'.format(args.prefix, workload)
                    output_obj = pathlib.Path(args.output.resolve(), fileName)
                    with open(output_obj, 'w') as outFile:
                        logger.debug('Path: {}'.format(output_obj))
                        json.dump(results[workload], outFile)

    logger.info('Export complete, terminating')
