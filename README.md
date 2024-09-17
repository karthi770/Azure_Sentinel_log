Azure Sentinel
1. Creating a VM and the resource group:

	Basic tab:
	![image](https://github.com/user-attachments/assets/9c119232-1c64-463b-aadd-3e79c75f7417)
	![image](https://github.com/user-attachments/assets/15ad475f-37af-407f-b2ad-89c14767d08e)
	![image](https://github.com/user-attachments/assets/298a269e-0da1-465d-a770-81a509b84b3a)
	![image](https://github.com/user-attachments/assets/21342b2e-5983-448e-8e5d-aae9175447fc)
	![image](https://github.com/user-attachments/assets/a3832423-49d7-4ddc-ae78-dcf5c53ea37f)

	Networking tab:
	![image](https://github.com/user-attachments/assets/0fffe750-0e63-4712-b0af-3a9ca2d8346c)
>[!info]
>Inside the networking tab create a new security group that will allow all the traffic inside the VM.


![image](https://github.com/user-attachments/assets/8f18f6f0-c86b-40ca-87c8-4edf541dbcd2)![image](https://github.com/user-attachments/assets/6598fa36-5df3-4cc2-83dd-e0da51c13935)
These settings are enough for now and we can go ahead and create the Virtual machine.

2. Create the Log analytics workspace
	![image](https://github.com/user-attachments/assets/16ab41ab-dc7b-4f23-bf34-70114fc4216c)
	Click Review + Create and then click on Create at the end of the page.

3. Security Center (Renamed as MS Defender)
		![image](https://github.com/user-attachments/assets/6f7f506b-e741-4438-8086-b95a250ef475)
		Go to the environment settings and enable the defender for honeypot log.
		![image](https://github.com/user-attachments/assets/1ad7b780-7eb0-4e27-9cb5-e614026f4075)
		![image](https://github.com/user-attachments/assets/0513a4e0-43fa-4f23-9ced-5e02814e03b6)
	Now Go to Log analystics workspace and connect to the VM:
	![image](https://github.com/user-attachments/assets/f46ea944-685a-436b-ab39-c44482efe06f)
	Now go to Azure Sentinel and and add Sentinel to a workspace:
		![image](https://github.com/user-attachments/assets/ff78a0d1-faa1-46e4-86f0-a2837e8328ce)
		

Connect to the VM:
![image](https://github.com/user-attachments/assets/39fd94ee-6a8a-4839-92b0-98ca74369f51)
![image](https://github.com/user-attachments/assets/3cc0f24f-155b-4fe7-b094-8f47cc76ec25)
>[!info]
>Once I deliberately failed the login and the the Event viewer as recorded it, if we get into the log we can find the details of the user trying to login and their IP address, which we can use to visualize.
>


![image](https://github.com/user-attachments/assets/da4626af-ff28-4613-b0c8-5d7b587b0fe8)
Tried to ping the VM from the local machine and it failed.

![image](https://github.com/user-attachments/assets/b4c2c59c-c219-45ad-ae51-1daa4a06c6ff)
Now to the RDP and disable the firewall. Go to all tabs (private, public) and off the state.

To get the IP location of the people logging in we need the API key of a site that will help us track the IP addresses. Sign in and get the IP.
![image](https://github.com/user-attachments/assets/072a89ba-ddb8-45a4-b30b-02bd8fe64459)

```powershell
# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "ea3568b7f55c49be927ec47f9de8e3b1"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

<#
    This function creates a bunch of sample log files that will be used to train the
    Extract feature in Log Analytics workspace. If you don't have enough log files to
    "train" it, it will fail to extract certain fields for some reason -_-.
    We can avoid including these fake records on our map by filtering out all logs with
    a destination host of "samplehost"
#>
Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-5.32558,longitude:100.28595,destinationhost:samplehost,username:Test,sourcehost:42.1.62.34,state:Penang,country:Malaysia,label:Malaysia - 42.1.62.34,timestamp:2021-10-26 11:04:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:41.05722,longitude:28.84926,destinationhost:samplehost,username:AZUREUSER,sourcehost:176.235.196.111,state:Istanbul,country:Turkey,label:Turkey - 176.235.196.111,timestamp:2021-10-26 11:50:47" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:55.87925,longitude:37.54691,destinationhost:samplehost,username:Test,sourcehost:87.251.67.98,state:null,country:Russia,label:Russia - 87.251.67.98,timestamp:2021-10-26 12:13:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37018,longitude:4.87324,destinationhost:samplehost,username:AZUREUSER,sourcehost:20.86.161.127,state:North Holland,country:Netherlands,label:Netherlands - 20.86.161.127,timestamp:2021-10-26 12:33:46" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:17.49163,longitude:-88.18704,destinationhost:samplehost,username:Test,sourcehost:45.227.254.8,state:null,country:Belize,label:Belize - 45.227.254.8,timestamp:2021-10-26 13:13:25" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-55.88802,longitude:37.65136,destinationhost:samplehost,username:Test,sourcehost:94.232.47.130,state:Central Federal District,country:Russia,label:Russia - 94.232.47.130,timestamp:2021-10-26 14:25:33" | Out-File $LOGFILE_PATH -Append -Encoding utf8
}

# This block of code will create the log file if it doesn't already exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

# Infinite Loop that keeps checking the Event Viewer logs.
while ($true)
{
    
    Start-Sleep -Seconds 1
    # This retrieves events from Windows EVent Viewer based on the filter
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    if ($Error) {
        #Write-Host "No Failed Logons found. Re-run script when a login has failed."
    }

    # Step through each event collected, get geolocation
    #    for the IP Address, and add new events to the custom log
    foreach ($event in $events) {


        # $event.properties[19] is the source IP address of the failed logon
        # This if-statement will proceed if the IP address exists (>= 5 is arbitrary, just saying if it's not empty)
        if ($event.properties[19].Value.Length -ge 5) {

            # Pick out fields from the event. These will be inserted into our new custom log
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year

            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }

            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }

            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }


            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }

            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceHost = $event.properties[11].Value # Workstation Name (Source)
            $sourceIp = $event.properties[19].Value # IP Address
        

            # Get the current contents of the Log file!
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Do not write to the log file if the log already exists.
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                # Announce the gathering of geolocation data and pause for a second as to not rate-limit the API
                #Write-Host "Getting Latitude and Longitude from IP Address and writing to log" -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            else {
                # Entry already exists in custom log file. Do nothing, optionally, remove the # from the line below for output
                # Write-Host "Event already exists in the custom log. Skipping." -ForegroundColor Gray -BackgroundColor Black
            }
        }
    }
}
```
Use the above PS script and change the API key, run the script in the VM.

![image](https://github.com/user-attachments/assets/df900e0d-2791-4ee9-b640-17c885de49a8)
We shall we a log like this where people have tried to log in and failed.

Below is the snap of the log file which has the details that were scraped from the IP geolocation website and show it in the notepad.
![image](https://github.com/user-attachments/assets/982c6a2b-dba5-4b5b-ab19-8bbcb726224a)

Create a Custom log:

Go to the Azure portal and in the log analytics workspace create custom log:
![image](https://github.com/user-attachments/assets/465f4ef6-25c9-49b4-9fc3-3e7772eb8c24)

Copy all the data from the log file we saw in RDP and create a log file in the local desktop and paste the data, this will server as the sample file to train the log analytics workspace.
![image](https://github.com/user-attachments/assets/080a46d3-479c-431a-9b6b-24f6fa648a0e)

![image](https://github.com/user-attachments/assets/c37da7fc-b2a4-431e-86b0-374274cba3b7)

![image](https://github.com/user-attachments/assets/355866a8-2d2b-455a-bdbc-5d3b69ce4c20)

![image](https://github.com/user-attachments/assets/abdeebf4-404a-40c2-97ba-5e86989bf703)
>[!iimportant]
>The path entered in the collection path is the path of the log file that is stored in the RDP Program Data folder.

![image](https://github.com/user-attachments/assets/657c67ed-571d-48f3-852f-daed41858108)

![image](https://github.com/user-attachments/assets/b71e732d-9816-4ee7-a4d5-9ac72613631c)
If we run a query in the Log analytics workspace we shall get the following result.

![image](https://github.com/user-attachments/assets/30697d11-ec94-4883-8efb-081150bb66ae)
Now when we try to look into our log file we can find the RAW data that as been stored and we need to extract some of the fields that we need.

```SQL
FAILED_RDP_WITH_GEO_LOC_CL
| parse RawData with "latitude:" Latitude ",longitude:" Longitude ",destinationhost:" DestinationHost ",username:" Username ",sourcehost:" SourceHost ",state:" State ",country:" Country ",label:" Label ",timestamp:" Timestamp
| project Latitude, Longitude, Country, Timestamp, Label
```
![image](https://github.com/user-attachments/assets/753fefa3-448e-4161-aac1-4862b6d960d8)

Now go to Sentinel and Create work books 
![image](https://github.com/user-attachments/assets/9b946b8f-9563-46a1-80e8-6d6bd5b803dc)

![image](https://github.com/user-attachments/assets/b1dee1f9-da1d-44b8-baa4-ca4c5c59550b)
Click on Add query

```SQL
FAILED_RDP_WITH_GEO_LOC_CL
| parse RawData with "latitude:" Latitude ",longitude:" Longitude ",destinationhost:" DestinationHost ",username:" Username ",sourcehost:" SourceHost ",state:" State ",country:" Country ",label:" Label ",timestamp:" Timestamp
| project Latitude, Longitude, Country, Timestamp, Label, SourceHost
| where SourceHost != ""
```

![image](https://github.com/user-attachments/assets/4ccb6db2-17cd-4e68-a90d-c9775ead2355)

![image](https://github.com/user-attachments/assets/291603d4-09b0-4661-b392-bbffdf4d62da)
Select the map setting for better visualization.

The query needs to be changed to summarize the events:
```SQL
FAILED_RDP_WITH_GEO_LOC_CL
| parse RawData with "latitude:" Latitude ",longitude:" Longitude ",destinationhost:" DestinationHost ",username:" Username ",sourcehost:" SourceHost ",state:" State ",country:" Country ",label:" Label ",timestamp:" Timestamp
| project Latitude, Longitude, Country, Timestamp, Label, SourceHost
| where SourceHost != ""
| summarize event_count=count() by SourceHost, Latitude, Longitude, Country, Label
```

![image](https://github.com/user-attachments/assets/8aa90096-d43d-4696-8abe-35274f66f9d2)
![image](https://github.com/user-attachments/assets/8ee652de-9230-4989-86af-e8f79d7fa696)
In the map setting these metric settings needs to be changed to get a better visualization.
