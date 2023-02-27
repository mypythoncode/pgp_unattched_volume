import boto3
import time
import os
import logging
from ec2_metadata import ec2_metadata
from botocore.exceptions import ClientError
import json
from subprocess import Popen, PIPE
from threading import Timer


class EC2Client(object):

    ec2_client = boto3.client('ec2', region_name = ec2_metadata.region)
    zone = None
    instance_id = None
        device_name = '/dev/xvdf'
    mount_path = '/mnt/pgp'
    service_user = 'ec2-user'
    kms_alias = 'alias/KMS-SFTP-PGP-PRD'
    # times of 2 seconds
    time_out = 60
    volume_id = None

    def __init__(self):
        # Assume a role
        self.zone = ec2_metadata.availability_zone
        self.instance_id = ec2_metadata.instance_id


    def get_volume_attachment_state(self, volume_id):
        """
        Get the volume attachment state
        :param volume_id The volume ID
        """
        try:
            resp = self.ec2_client.describe_volumes(VolumeIds=[volume_id])
            # State': 'attaching'|'attached'|'detaching'|'detached'|'busy'
            logging.debug('Volume %s attachment response: %s', volume_id, resp )
            logging.info('Volume %s attachment state: %s', volume_id, resp['Volumes'][0]['Attachments'][0]['State'] )
            return resp['Volumes'][0]['Attachments'][0]['State']
        except Exception as e:
            logging.exception('Error in getting volume attachment state: %s', e)
            return None


    def get_volume_running_state(self, volume_id):
        """
        Get the volume current state
        :param volume_id The volume ID
        """
        try:
            resp = self.ec2_client.describe_volumes(VolumeIds=[volume_id])
            # 'State': 'creating'|'available'|'in-use'|'deleting'|'deleted'|'error'
            logging.debug('Volume %s running response: %s', volume_id, resp )
            logging.info('Volume %s running state: %s', volume_id,  resp['Volumes'][0]['State'] )
            return resp['Volumes'][0]['State']
        except Exception as e:
            logging.exception('Error in getting volume running state: %s', e)
            return None


    def attach_new_volume(self, size, customer):
        """
        Create a new volume and attach to 
        :param size The volume size (GB)
        :param customer The customer to tag the volume
        :return: The volume ID
        """
        # Create new volume
        tag = [
            {
                'ResourceType': 'volume',
                'Tags': [
                    {
                        'Key': 'fico:sftp:customer',
                        'Value': customer 
                    },
                    {
                        'Key': 'Name',
                        'Value': 'SFTP PGP Transform'
                    },
                    {
                        'Key': 'fico:billing:service',
                        'Value': 'SFTP' 
                    },
                    {
                        'Key': 'fico:billing:tenant',
                        'Value': 'Shared' 
                    },
                    {
                        'Key': 'fico:common:owner',
                        'Value': 'AWS Cloud Engineering' 
                    },
                    {
                        'Key': 'fico:common:business-service',
                        'Value': 'Infrastructure-AWS_GTS_Services-FICO_Internal' 
                    },
                    {
                        'Key': 'fico:ebs:backup',
                        'Value': 'false' 
                    }
                ]
            }
        ]
        vol_id = None
        try:
            # Detach the volume if there's an expired volume
            if EC2Client.volume_id:
                logging.info('Expired volume is detected and will be removed: %s' % EC2Client.volume_id)
                self.uninstall_volume(EC2Client.volume_id)

            # Create new volume 
            logging.info('Creating the volume...')

            # Set volume size equal to the greater of the passed / calculated volume size or 1GB
            size = size if size > 1 else 1

            resp = self.ec2_client.create_volume(AvailabilityZone=self.zone, Size=size, TagSpecifications=tag, VolumeType='gp2'
                    , Encrypted=True, KmsKeyId=self.kms_alias)
            vol_id = resp['VolumeId']
            EC2Client.volume_id = resp['VolumeId']
            time_out_cnt = 0
            while self.get_volume_running_state(vol_id) != 'available':
                time.sleep(2)
                if time_out_cnt < self.time_out:
                    time_out_cnt +=1
                else:
                    raise RuntimeError('Timeout in creating the volume: %s' % vol_id)
            logging.info('Volume "%s" is created: size: %sG, customer: %s', vol_id, size, customer)

            logging.info('Attaching the volume...')
            resp = self.ec2_client.attach_volume(Device=self.device_name, InstanceId=self.instance_id, VolumeId=vol_id)
            time_out_cnt = 0
            while self.get_volume_attachment_state(vol_id) != 'attached':
                time.sleep(2)
                if time_out_cnt < self.time_out:
                    time_out_cnt += 1
                else:
                    raise RuntimeError('Timeout in attaching the volume %s' % vol_id)
            logging.info('Volume %s is attached to instance %s', resp['VolumeId'], resp['InstanceId'])
        except Exception as err:
            
            # Create Generic Log entry to be used for CloudWatch event trigger
            logging.error('AWS SFTP PGP EC2 client error - availability_zone: %s volume_size: %s customer: %s', self.zone, size, customer)

            if vol_id:
                logging.error('Error in creating/attaching a new volume: %s', vol_id)
            else:
                logging.error('Error in creating a new volume')
            raise err
        finally:
            return vol_id
        

    # def remove_volume(self, volume_id):
    #     """
    #     Detach and delete the volume
    #     :param volume_id The volume ID
    #     """
    #     try:
    #         time_out_cnt = 0
    #         detach_sent = False
    #         while True:
    #             attach_state = self.get_volume_running_state(volume_id)
    #             if attach_state == 'available':
    #                 # Ready to delete the volume
    #                 logging.info('Volume is available to be deleted: %s', volume_id)
    #                 break
    #             elif attach_state == 'in-use':                    
    #                 # Detach the volume
    #                 if not detach_sent:
    #                     logging.info('Detach the volume: %s', volume_id)
    #                     self.ec2_client.detach_volume(VolumeId=volume_id)
    #                     detach_sent = True
    #             elif attach_state == 'deleting' or attach_state == 'deleted':
    #                 logging.info('Volume is deleted or going to be deleted: %s', volume_id)
    #                 return True
    #             elif attach_state == 'error':
    #                 raise Exception('Volume is in error state: %s' % volume_id)
             
    #             if time_out_cnt < self.time_out:
    #                 time_out_cnt += 1
    #                 time.sleep(2)
    #             else:
    #                 raise RuntimeError('Timeout in detaching the volume: %s' % volume_id)  
            
    #         # Remove the volume
    #         self.ec2_client.delete_volume(VolumeId=volume_id)
    #         EC2Client.volume_id = None
    #         logging.info('Volume is going to be deleted: %s', volume_id)

    #         return True
    #     except Exception as err:
    #         logging.error('Fail in deleting the volume: %s', volume_id)
        
    
    def remove_volume(self, volume_id):
        try:

            # Detach volume before deletion
            attachment = self.ec2_client.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]['Attachments']
            if attachment:
                self.ec2_client.detach_volume(VolumeId=volume_id, Force=True)
                self.ec2_client.get_waiter('volume_available').wait(VolumeIds=[volume_id])
            
            # Delete the volume
            response = self.ec2_client.delete_volume(VolumeId=volume_id)
            logging.info('Successfully deleted EBS volume %s', volume_id)
            return response
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'VolumeInUse':

                # wait for some time and retry
                time.sleep(30)
                response = self.ec2_client.delete_volume(VolumeId=volume_id)
                logging.info('Successfully deleted EBS volume %s after retry', volume_id)
                return response
            elif error_code == 'InvalidVolume.NotFound':

                 # Volume not found, do nothing
                 return None
            else:
            
                # Raise alarm for manual intervention
                cloudwatch = boto3.client('cloudwatch')
                cloudwatch.put_metric_data(
                    MetricData=[
                        {
                             'MetricName': 'EBS Volume Deletion Failure',
                             'Dimensions': [
                                 {
                                     'Name': 'VolumeId',
                                     'Value': volume_id
                                 },
                             ],
                             'Unit': 'None',
                             'Value': 1
                       },
                   ],
                   Namespace='EBS_Volumes'
                )
                logging.exception('Error deleting EBS volume %s: %s', volume_id, e)

    
    def terminal_call(self, command_str, timeout_sec=5):
        """
        Execute the shell command and return the output
        :param command_str The command to execute
        :param timeout_sec The time for running the command
        :return: The running output 
        """
        # Popen returns a tuple (stdout, stderr)
        commands = command_str.split(' ')
        print (commands)
        p = Popen(commands, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        timer = Timer(timeout_sec, p.kill)

        try:
            timer.start()
            return p.communicate()
        finally:
            timer.cancel()
    

    def mount_volume(self):
        """
        Mount the volume
        :return: The path to the mounted volume
        """
        logging.info('Start mount the device...')
        cmd = 'sudo mkfs -t xfs %s' % self.device_name
        logging.info(self.terminal_call(cmd))

        if os.path.exists(self.mount_path):
            # Remove the existing one
            cmd = 'sudo rm %s' % self.mount_path
            logging.info(self.terminal_call(cmd))
        else:
            logging.info('No folder %s exist. Create a new one.', self.mount_path)

        cmd = 'sudo mkdir %s' % self.mount_path
        logging.info(self.terminal_call(cmd))

        cmd = 'sudo mount %s %s' % (self.device_name, self.mount_path)
        logging.info(self.terminal_call(cmd))

        cmd = 'sudo chown %s %s' % (self.service_user, self.mount_path)
        logging.info(self.terminal_call(cmd))
        return self.mount_path

    def unmount_volume(self):
        """
        Unmount the volume
        """
        try:
            logging.info('Start umount the device...')
            cmd = 'sudo umount -d %s' % self.mount_path
            logging.info(self.terminal_call(cmd))
            cmd = 'sudo rm -rf %s' % self.mount_path
            logging.info(self.terminal_call(cmd))
        except Exception as err:
            logging.error('Fail in unmounting the volume: %s', self.volume_id)

    
    def install_volume(self, size, customer):
        """
        Create, attach and mount a new volume
        :return: The path to the mounted volume
        """
        vol_id = self.attach_new_volume(size, customer)
        mnt_path = self.mount_volume()
        return {'volume_id':vol_id, 'mount_path': mnt_path}


    def uninstall_volume(self, vol_id):
        """
        Unmound, detach and delete the volume
        """
        self.unmount_volume()
        return self.remove_volume(vol_id)
