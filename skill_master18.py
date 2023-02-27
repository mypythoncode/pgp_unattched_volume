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
