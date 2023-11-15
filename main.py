import xml.etree.ElementTree as ET
import os
import openai

# --- Config ------------------------------------------------

file_path = 'logs.xml'
elements_each_iteration = 100
apiKey = "<api-token>"
model = "gpt-4"


# -----------------------------------------------------------

# This function imports Sysmon logs from an XML file.
def import_sysmon_logs(file_path):
    try:
        tree = ET.parse(file_path)
        return tree.getroot()
    except FileNotFoundError:
        print("File not found. Please check the path and try again.")
        return None
    except ET.ParseError:
        print("Error parsing XML. Please check the file format.")
        return None


# This function removes the namespace from the XML tag.
def strip_namespace(tag):
    if '}' in tag:
        return tag.split('}', 1)[1]
    return tag


# Extracts log entries from the XML root, including element attributes and text.
def extract_log_entries(root):
    entries = []
    for event in root.findall('.//{*}Event'):
        entry = {'Event': {'System': {}, 'EventData': []}}
        for child in event:
            tag = strip_namespace(child.tag)
            if tag == 'System':
                for element in child:
                    subtag = strip_namespace(element.tag)
                    element_detail = {
                        'text': element.text,
                        'attributes': element.attrib
                    }
                    entry['Event']['System'][subtag] = element_detail
            elif tag == 'EventData':
                for data_element in child.findall('.//{*}Data'):
                    data = {
                        'Name': data_element.get('Name'),
                        'Value': data_element.text,
                        'attributes': data_element.attrib
                    }
                    entry['Event']['EventData'].append(data)
        entries.append(entry)
    return entries


# Function to count existing report files and create a new file name
def get_new_report_file():
    existing_reports = [f for f in os.listdir('.') if f.startswith('report_') and f.endswith('.txt')]
    new_report_number = len(existing_reports) + 1
    return f"report_{new_report_number}.txt"


# Function to create GPT prompts and write summaries
def analyze_and_summarize(entries, type):
    openai.api_key = apiKey
    text = (
        f"The entries in the XML is from {type} logs. Analyze them and report anything that looks suspicous or malicous. Make sure to add UTC, ProcessID, EventID, Task, and UserID for the entries you find suspicious. Make the summary short and concrete. If you find anything worth looking at, start the report with \"!!ALERT!!\". An agent will make a full summary of your and other agetns smaller reports. Another agent will make a Timeline from potential attacks. Take this into consideration when making the report. The entries: {entries}")
    completion = openai.chat.completions.create(model=model, messages=[{"role": "user", "content": text}])

    summary = f"Summary of Analysis:\n{completion.choices[0].message.content}\n-------------------------------\n"

    report_file_name = get_new_report_file()
    with open(report_file_name, 'a') as file:
        file.write(summary)


# Main analysis loop
def main_analysis(entries):
    total_iterations = len(entries) // elements_each_iteration

    # Let the user define what type of log it is.
    type = input("What type of log is this? [Application, Sysmon etc...]: ")

    print("Thank you! Starting first iteration.")

    # Process in batches
    for i in range(0, len(entries), elements_each_iteration):
        batch = entries[i:i + elements_each_iteration]
        # print(batch)
        analyze_and_summarize(batch, type)
        print(f"Done with iteration {i // elements_each_iteration + 1} out of {total_iterations + 1}")

    print(f"Analysis completed. Reports saved in {get_new_report_file()}")


# Function to read all reports and combine their content
def read_all_reports():
    report_files = [f for f in os.listdir('.') if f.startswith('report_') and f.endswith('.txt')]
    combined_content = ""
    for file_name in report_files:
        with open(file_name, 'r') as file:
            combined_content += file.read() + "\n"
    return combined_content


# Function to create a final summary using GPT
def create_final_summary(content):
    openai.api_key = apiKey
    prompt = (
        f"Analyze the following reports and provide a concise summary that highlights only the most certain and "
        f"significant findings. Focus on areas that strongly indicate potential issues or require immediate "
        f"attention. Avoid including speculative or less certain observations. The reports: {content}")
    completion = openai.chat.completions.create(model=model, messages=[{"role": "user", "content": prompt}])

    # Generated summary
    summary = completion.choices[0].message.content

    # Save the summary
    with open("Summary.txt", 'w') as file:
        file.write(summary)


# Function to create a timeline using GPT
def create_attack_timeline(content):
    openai.api_key = apiKey
    prompt = (
        f"Create a timeline of potential attacks based on the following reports, focusing on key dates, times, "
        f"and sequences of events. Only create a clear timeline with comments. After that make a keyword list with "
        f"keywords to help the analyst finding suspicious/malicious logs. Another agent is writing a summary, "
        f"you do not need to do that. The reports: {content}")
    completion = openai.chat.completions.create(model=model, messages=[{"role": "user", "content": prompt}])

    # Generated timeline
    timeline = completion.choices[0].message.content

    # Save the timeline
    with open("AttackTimeline.txt", 'w') as file:
        file.write(timeline)


# Usage
if __name__ == "__main__":
    root = import_sysmon_logs(file_path)
    if root is not None:
        print("Logs imported successfully!")
        entries = extract_log_entries(root)
        print(f"Starting analysis with {len(entries)} entries...")
        main_analysis(entries)
        print("Generating final summary...")
        combined_reports = read_all_reports()
        create_final_summary(combined_reports)
        print("Final summary saved in Summary.txt")
        print("Generating attack timeline...")
        combined_reports = read_all_reports()
        create_attack_timeline(combined_reports)
        print("Attack timeline saved in AttackTimeline.txt")
    else:
        print("No logs found.")
