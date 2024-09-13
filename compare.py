import boto3
import requests
import time

def compare_cloud_services(image_data):
    # AWS Lambda settings
    aws_client = boto3.client('lambda', region_name='ap-south-1')
    lambda_function_name = 'my_image_conversion'

    # Azure Functions settings
    azure_function_url = 'https://imageconversions.azurewebsites.net'

    # Measure AWS Lambda execution time
    start_time = time.time()
    aws_response = aws_client.invoke(
        FunctionName=lambda_function_name,
        Payload=image_data,
        InvocationType='RequestResponse'
    )
    aws_execution_time = (time.time() - start_time) * 1000  # Convert to ms

    # Measure Azure Functions execution time
    start_time = time.time()
    azure_response = requests.post(azure_function_url, files={'image': image_data})
    azure_execution_time = (time.time() - start_time) * 1000  # Convert to ms

    # Mock cost calculation for example purposes
    aws_cost = calculate_aws_cost(aws_response)
    azure_cost = calculate_azure_cost(azure_response)

    # Return a dictionary with results
    return {
        'aws_execution_time': aws_execution_time,
        'azure_execution_time': azure_execution_time,
        'aws_cost': aws_cost,
        'azure_cost': azure_cost,
        'aws_scalability_tests': 'Test data pending',
        'azure_scalability_tests': 'Test data pending',
        'aws_setup_time': 10,  
        'azure_setup_time': 8   
    }

def calculate_aws_cost(response):

    return 0.00001667  
def calculate_azure_cost(response):
    return 0.000016

# Example usage
if __name__ == "__main__":
    with open('path_to_your_image_file', 'rb') as f:
        image_data = f.read()
    results = compare_cloud_services(image_data)

    # Print the results (or pass them to your Flask app)
    print(results)
