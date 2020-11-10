# requisite packages for convert_pcap_to_df and network_analysis functions
from scapy.all import * # Packet manipulation
import binascii # pcap data type binary to ascii
import pandas as pd # dataframe manipulation
import numpy as np # math
from matplotlib import pyplot as plt #visualization

# converts the pcap to a dataframe for manipulation
def convert_pcap_to_df(pcap):
    # Collect field names from IP/TCP/UDP (These will be columns in DF)
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex']

    # Create blank DataFrame
    df = pd.DataFrame(columns=dataframe_fields)
    for packet in pcap[IP]:
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])

        field_values.append(packet.time)
        layer_type = type(packet[IP].payload)

        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)

        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)

    # Reset Index
    df = df.reset_index()
    # Drop old index column
    df = df.drop(columns="index")
    # return df
    return(df)

# performs network analysis on pcap file at given destination
def network_analysis(data_path):
    # use rdpcap to read pcap file from data_path
    pcap = rdpcap(data_path)

    # convet pcap variable to dataframe
    df = convert_pcap_to_df(pcap)

    # get statistical info:
    # get top addresses
    # top source adddress
    print("Top Source Address")
    print(df['src'].describe(),'\n\n')
    # top destination Address
    print("Top Destination Address")
    print(df['dst'].describe(),"\n\n")
    # get info on top address
    frequent_address = df['src'].describe()['top']
    # who is the top address speaking to
    print("Who Top Address Speaking to?")
    print(df[df['src'] == frequent_address]['dst'].unique(),"\n\n")
    # Who is the top address speaking to (dst ports)
    print("Who the top address speaking to (Destination Ports)")
    print(df[df['src'] == frequent_address]['dport'].unique(),"\n\n")
    # Who is the top address speaking to (src ports)
    print("Who the top address speaking to (Source Ports)")
    print(df[df['src'] == frequent_address]['sport'].unique(),"\n\n")
    # get unique addresses
    # Unique Source Addresses
    print("Unique Source Addresses")
    print(df['src'].unique())
    # Unique Destination Addresses
    print("Unique Destination Addresses")
    print(df['dst'].unique())

    # create various visuals
    # Group by Source Address and Payload Sum
    source_addresses = df.groupby("src")['payload'].sum()
    source_addresses.plot(kind='barh',
                          title="Addresses Sending Payloads",figsize=(10,8));
    plt.show()

    # Group by Source Port and Payload Sum
    source_payloads = df.groupby("sport")['payload'].sum()
    # create cutoff to limit number of entries
    sp_cutoff_high = source_payloads.quantile(0.95)
    sp_cutoff_low = source_payloads.quantile(0.05)
    # split the data by cutoff
    source_payloads_filtered_high = source_payloads[source_payloads
                                                    > sp_cutoff_high]
    source_payloads_filtered_low = source_payloads[source_payloads
                                                   < sp_cutoff_low]
    #plot
    source_payloads_filtered_high.plot(kind='barh',
                         title="Top Quantile Source Ports (Bytes Sent)",
                         figsize=(10,8));
    plt.show()
    source_payloads_filtered_low.plot(kind='barh',
                         title="Bottom Quantile Source Ports (Bytes Sent)",
                         figsize=(10,8));
    plt.show()

    # Group by Destination Address and Payload Sum
    destination_addresses = df.groupby("dst")['payload'].sum()
    destination_addresses.plot(kind='barh',
                               title="Destination Addresses (Bytes Received)",
                               figsize=(10,8));

    # Group by Destination Port and Payload Sum
    destination_payloads = df.groupby("dport")['payload'].sum()
    # create cutoff to limit number of entries
    dp_cutoff_high = destination_payloads.quantile(0.95)
    dp_cutoff_low = destination_payloads.quantile(0.005)
    # split data by cutoff
    destination_payloads_high = destination_payloads[destination_payloads
                                                     > dp_cutoff_high]
    destination_payloads_low = destination_payloads[destination_payloads
                                                    > dp_cutoff_low]
    #plot
    destination_payloads_high.plot(kind='barh',
                              title="Top Quantile Destination Ports (Bytes Received)",
                              figsize=(10,8));
    plt.show()
    destination_payloads_low.plot(kind='barh',
                              title="Bottom Quantile Destination Ports (Bytes Received)",
                              figsize=(10,30));
    plt.show()

    # filtered bytes sent by frequent_addresses
    # subset data to frequent addresses with bytes in top quantile
    frequent_address_df = df[df['src'] == frequent_address]
    frequent_address_subdf = frequent_address_df[['time', 'payload']].set_index('time')
    # create cutoffs
    bfa_cutoff_high = frequent_address_subdf.payload.quantile(0.95)
    bfa_cutoff_low = frequent_address_subdf.payload.quantile(0.005)
    # split data by cutoffs
    frequent_address_high = frequent_address_subdf[frequent_address_subdf
                                                    > bfa_cutoff_high]
    frequent_address_high.dropna(axis=0, inplace=True)
    frequent_address_low = frequent_address_subdf[frequent_address_subdf
                                                  > bfa_cutoff_low]
    frequent_address_low.dropna(axis=0, inplace=True)
    #plot frequent addresses with most bytes sent
    frequent_address_high.plot(kind='barh',
                                title="Top Quantile Bytes sent by most frequent addresses",
                                figsize=(10,8));
    plt.show()
    frequent_address_low.plot(kind='barh',
                                title="Bottom Quantile Bytes sent by most frequent addresses",
                                figsize=(10,30));
    plt.show()

    # Explore payloads
    # Create dataframe with only converation from most frequent address
    frequent_address_df = df[df['src']==frequent_address]

    # Only display Src Address, Dst Address, and group by Payload
    frequent_address_groupby = frequent_address_df[['src',
                                                    'dst','payload']].groupby("dst")['payload'].sum()

    # Plot the Frequent address is speaking to (By Payload)
    frequent_address_groupby.plot(kind='barh',
                                  title="Most Frequent Address is Speaking To (Bytes)",
                                  figsize=(10,8))
    plt.show()

    # address excahnged the most bytes with most frequent address
    activity_ip = frequent_address_groupby.sort_values(ascending=False).index[0]
    print(activity_ip, "has a lot of activity... check out the activity in activity_df")

    # dataframe with only conversation from most frequent address
    activity_df = frequent_address_df[frequent_address_df['dst']==activity_ip]
    return(activity_df)
