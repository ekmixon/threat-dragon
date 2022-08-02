import logger as log
import mail
import json

def read_json(threatJasonPath):
    try:
        with open(threatJasonPath, 'r') as JSON_file:
            dataTM = JSON_file.read()
        return json.loads(dataTM)

    except FileNotFoundError as e2:
         log.logger.error("File not accessible")
         mail.sendErrorEmail("Threat Model: Exception occurred reading the JSON file", e)  
         log.logger.info(f'Finish processing \n')
         raise e2
    except Exception as e:
         log.logger.error("Exception occurred", exc_info=True)
         mail.sendErrorEmail("Threat Model: Exception occurred reading the JSON file", e)  
         log.logger.info(f'Finish processing \n')
         raise e