|     | Column Name    | Data Type   | Description   |
| --- | --- | --- | --- |
| 1   | flow\_id | string | A unique identifier for the network flow (e.g., a hash of the 5-tuple). |
| 2   | src\_ip | string | Source IP address of the flow. |
| 3   | dst\_ip | string | Destination IP address of the flow. |
| 4   | src\_port | int | Source port number. |
| 5   | dst\_port | int | Destination port number. |
| 6   | protocol | string or int | The transport layer protocol (e.g., 'TCP', 'UDP'). |
| 7   | application\_label | string | The ground-truth label for the application (your target variable). |
| 8   | packet\_size\_sequence | object (list of int) | The ordered sequence of packet lengths (including headers) for the flow. |
| 9   | packet\_size\_mean | float | The average size of packets in the flow. |
| 10  | packet\_size\_median | float | The median packet size. |
| 11  | packet\_size\_std | float | The standard deviation of packet sizes. |
| 12  | packets\_to\_server | int | Total number of packets sent from client to server. |
| 13  | packets\_from\_server | int | Total number of packets sent from server to client. |
| 14  | packet\_count\_total | int | Total number of packets in the flow. |
| 15  | packet\_ratio | float | Ratio of packets sent to received. |
| 16  | total\_bytes\_sent | int | Total number of bytes sent from client to server. |
| 17  | total\_bytes\_received | int | Total number of bytes sent from server to client. |
| 18  | total\_bytes | int | Total bytes in the flow. |
| 19  | payload\_size\_mean | float | The average payload size (excluding headers) for the flow. |
| 20  | flow\_start\_time | datetime or int | Timestamp of the first packet in the flow. |
| 21  | flow\_end\_time | datetime or int | Timestamp of the last packet in the flow. |
| 22  | flow\_duration | float | Total duration of the flow in seconds. |
| 23  | iat\_sequence | object (list of float) | The ordered sequence of inter-arrival times. |
| 24  | iat\_mean | float | The average inter-arrival time. |
| 25  | iat\_std | float | The standard deviation of inter-arrival times. |
| 26  | burstiness | float | A measure of traffic "lumpiness." |
| 27  | server\_name\_indication | string | The Server Name Indication (SNI) from the TLS handshake. |
| 28  | client\_hello\_fingerprint | string | A unique string representing the Client Hello message. |