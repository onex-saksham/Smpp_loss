# SMPP PDU Chain Visualizer

## Usage
1. Input PCAP Directory:
Enter the address directory of your pcap files into the first input box. If no directory is provided, the project will automatically use pcap files from the base (project) directory.

2. Generate CSV:
Click the Generate CSV button. The code parses all pcap files in the chosen directory, regardless of file names, and saves the extracted data in CSV format for searching.

3. Download CSV:
To download the complete CSV for further operations (such as IP and port-based searching), click the Download Full Chain CSV button.

4. Search by Telco ID:
For searching a specific message chain, enter the Telco ID in the search bar. The following columns will be displayed, each showing information about the SMPP PDUs matching the Telco ID:

Table Columns Explained

| Column Name         | Description                                    |
| ------------------- | ---------------------------------------------- |
| `message_id`        | Unique ID assigned to the message by the telco |
| `submit_sm_seq`     | Sequence number of the `submit_sm` PDU         |
| `submit_sm_time`    | Timestamp when `submit_sm` was sent            |
| `submit_src`        | Source IP and port of `submit_sm`              |
| `submit_dst`        | Destination IP and port of `submit_sm`         |
| `submit_resp_seq`   | Sequence number of the `submit_sm_resp`        |
| `submit_resp_time`  | Timestamp when `submit_sm_resp` was received   |
| `deliver_seq`       | Sequence number of the `deliver_sm` PDU        |
| `deliver_time`      | Timestamp when `deliver_sm` was sent           |
| `deliver_src`       | Source IP and port of `deliver_sm`             |
| `deliver_dst`       | Destination IP and port of `deliver_sm`        |
| `deliver_resp_seq`  | Sequence number of the `deliver_sm_resp`       |
| `deliver_resp_time` | Timestamp when `deliver_sm_resp` was received  |
| `origin_addr`       | Sender's address (SMSC)                        |
| `recipient_addr`    | Recipient's mobile number                      |
| `dlvrd_status`      | Delivery report status (e.g., DELIVRD)         |
| `submit_date`       | Time the message was initially submitted       |
| `done_date`         | Time the delivery report was generated         |
| `status`            | Delivery status from the DLR                   |
| `error_code`        | SMPP error code (if any)                       |
| `message_text`      | Full message text payload                      |


## Requirements

- Python 3.x
- Django (see `requirements.txt` for exact version)
- Other dependencies as listed in `requirements.txt`

## Setup

1. **Clone the repository:**
    ```bash
    git clone git@github.com:onex-saksham/Smpp_loss.git
    cd smpp_visualizer
    ```

2. **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Apply migrations:**
    ```bash
    python manage.py migrate
    ```

5. **Create a superuser (optional, for admin access):**
    ```bash
    python manage.py createsuperuser
    ```

6. **Run the development server:**
    ```bash
    python manage.py runserver
    ```

7. **Access the project:**
    Open your browser and go to `http://127.0.0.1:8000/`


## Note
This an internal project for visualizing SMPP PDU chains within Onextel Network it should'nt be used in Production.