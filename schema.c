/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: JSON Schema for the event format.
 *
 * Documents the JSON shape that feed.c emits to stdout / UDP / MQTT /
 * ZMQ. Output by '--schema' so SIEM consumers can validate without
 * guessing. Any field added or renamed in feed.c should be reflected
 * here in the same commit.
 *
 * Schema format: JSON Schema 2020-12. Each top-level event variant is
 * an entry in `oneOf`; the `event` discriminator field selects which
 * one applies (absence of `event` means a regular packet event).
 */

#include "schema.h"

#include <stdio.h>

const char *schema_json_text(void)
{
    static const char SCHEMA[] =
"{\n"
"  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n"
"  \"$id\": \"https://github.com/cemaxecuter/meshtastic-sniffer/event.schema.json\",\n"
"  \"title\": \"meshtastic-sniffer event\",\n"
"  \"description\": \"One JSON object per emitted event. Packet events carry the radio header + per-port decoded fields; STATS / OFF_GRID_LORA / REPLAY_SUSPECTED carry a top-level 'event' discriminator.\",\n"
"  \"oneOf\": [\n"
"    { \"$ref\": \"#/$defs/PacketEvent\" },\n"
"    { \"$ref\": \"#/$defs/StatsEvent\" },\n"
"    { \"$ref\": \"#/$defs/OffGridEvent\" },\n"
"    { \"$ref\": \"#/$defs/ReplayEvent\" }\n"
"  ],\n"
"  \"$defs\": {\n"
"    \"PacketEvent\": {\n"
"      \"type\": \"object\",\n"
"      \"description\": \"A LoRa frame received from the mesh. Always carries 'from' and 'packet_id'; per-port decoded fields appear when the channel key is known and the payload parses.\",\n"
"      \"required\": [\"ts\", \"from\", \"to\", \"packet_id\", \"channel_hash\", \"hop_limit\", \"hop_start\"],\n"
"      \"not\": { \"required\": [\"event\"] },\n"
"      \"properties\": {\n"
"        \"station\":        { \"type\": \"string\", \"description\": \"--station-id value, when set\" },\n"
"        \"ts\":             { \"type\": \"number\", \"description\": \"Unix epoch seconds (host wall-clock)\" },\n"
"        \"from\":           { \"type\": \"string\", \"pattern\": \"^![0-9a-f]{8}$\", \"description\": \"sender node id\" },\n"
"        \"to\":             { \"type\": \"string\", \"pattern\": \"^![0-9a-f]{8}$\", \"description\": \"destination node id; !ffffffff = broadcast\" },\n"
"        \"packet_id\":      { \"type\": \"integer\", \"description\": \"sender-chosen packet identifier\" },\n"
"        \"channel_hash\":   { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 255, \"description\": \"1-byte channel hash from radio header (xorHash(name) ^ xorHash(psk))\" },\n"
"        \"slot_id\":        { \"type\": \"integer\", \"minimum\": 0, \"description\": \"polyphase channelizer slot index that caught this frame\" },\n"
"        \"station_t_ns\":   { \"type\": \"integer\", \"description\": \"first-replica realtime timestamp in nanoseconds since the Unix epoch; consumed by the fusion-side mlat solver\" },\n"
"        \"station_t_acc_ns\":{ \"type\": \"integer\", \"description\": \"self-reported timestamp accuracy class in ns: <=100 GPSDO+1PPS, <=10000 chrony+PPS, <=1000000 chrony+NTP, larger = unsynchronised\" },\n"
"        \"hop_limit\":      { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 7 },\n"
"        \"hop_start\":      { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 7 },\n"
"        \"relay_node\":     { \"type\": \"integer\", \"description\": \"upper byte of the relayer's node id when present\" },\n"
"        \"want_ack\":       { \"type\": \"boolean\" },\n"
"        \"via_mqtt\":       { \"type\": \"boolean\" },\n"
"        \"rssi_db\":        { \"type\": \"number\" },\n"
"        \"snr_db\":         { \"type\": \"number\" },\n"
"        \"payload_crc_ok\": { \"type\": \"boolean\", \"description\": \"only emitted when the LoRa CRC field was present on the wire; true=CRC verified, false=bytes corrupted in transit\" },\n"
"        \"fields_trusted\": { \"type\": \"boolean\", \"description\": \"true when from/to/packet_id/etc. are backed by positive verification (CRC pass OR successful AES decrypt + protobuf parse). False means the frame was a real-looking LoRa pattern but the decoded fields may be bit-corrupted -- do not display as a distinct sighting on a map / node list\" },\n"
"        \"cfo_hz\":         { \"type\": \"number\", \"description\": \"carrier frequency offset estimate; only emitted when |cfo| > 100 Hz\" },\n"
"        \"sf\":             { \"type\": \"integer\", \"minimum\": 7, \"maximum\": 12 },\n"
"        \"cr\":             { \"type\": \"integer\", \"minimum\": 5, \"maximum\": 8 },\n"
"        \"bw_hz\":          { \"type\": \"integer\" },\n"
"        \"preset\":         { \"type\": \"string\", \"enum\": [\"ShortTurbo\",\"ShortFast\",\"ShortSlow\",\"MediumFast\",\"MediumSlow\",\"LongFast\",\"LongMod\",\"LongSlow\",\"LongTurbo\"] },\n"
"        \"station_lat\":    { \"type\": \"number\" },\n"
"        \"station_lon\":    { \"type\": \"number\" },\n"
"        \"station_alt_m\":  { \"type\": \"number\" },\n"
"        \"decrypted\":      { \"type\": \"boolean\", \"description\": \"emitted only when false; absence implies decrypt succeeded\" },\n"
"        \"channel_name\":   { \"type\": \"string\", \"description\": \"human-readable channel label from decrypted metadata\" },\n"
"        \"portnum\":        { \"type\": \"integer\" },\n"
"        \"port_name\":      { \"type\": \"string\" },\n"
"        \"text\":           { \"type\": \"string\", \"description\": \"TEXT_MESSAGE_APP payload\" },\n"
"        \"lat\":            { \"type\": \"number\", \"description\": \"POSITION_APP latitude (deg)\" },\n"
"        \"lon\":            { \"type\": \"number\", \"description\": \"POSITION_APP longitude (deg)\" },\n"
"        \"alt_m\":          { \"type\": \"integer\" },\n"
"        \"time\":           { \"type\": \"integer\", \"description\": \"position fix time, unix seconds\" },\n"
"        \"sats\":           { \"type\": \"integer\" },\n"
"        \"speed_mps\":      { \"type\": \"integer\" },\n"
"        \"track_deg\":      { \"type\": \"integer\" },\n"
"        \"node_id\":        { \"type\": \"string\", \"description\": \"NODEINFO_APP self-reported id\" },\n"
"        \"long_name\":      { \"type\": \"string\" },\n"
"        \"short_name\":     { \"type\": \"string\" },\n"
"        \"hw_model\":       { \"type\": \"integer\" },\n"
"        \"role\":           { \"type\": \"integer\" },\n"
"        \"firmware\":       { \"type\": \"string\" },\n"
"        \"neighbors\":      { \"type\": \"array\", \"items\": {\n"
"            \"type\": \"object\",\n"
"            \"properties\": {\n"
"              \"id\":      { \"type\": \"string\" },\n"
"              \"snr_db\":  { \"type\": \"number\" }\n"
"            }\n"
"          }, \"description\": \"NEIGHBORINFO_APP\" },\n"
"        \"atak_callsign\":  { \"type\": \"string\" },\n"
"        \"atak_team\":      { \"type\": \"string\" },\n"
"        \"atak_role\":      { \"type\": \"string\" },\n"
"        \"atak_chat\":      { \"type\": \"string\" }\n"
"      }\n"
"    },\n"
"    \"StatsEvent\": {\n"
"      \"type\": \"object\",\n"
"      \"description\": \"5-second heartbeat with global throughput counters.\",\n"
"      \"required\": [\"event\", \"msps\", \"frames\", \"decrypted\"],\n"
"      \"properties\": {\n"
"        \"event\":     { \"const\": \"STATS\" },\n"
"        \"msps\":      { \"type\": \"number\", \"description\": \"input sample rate in millions of samples per second\" },\n"
"        \"frames\":    { \"type\": \"integer\", \"description\": \"cumulative LoRa frames decoded\" },\n"
"        \"decrypted\": { \"type\": \"integer\", \"description\": \"cumulative frames decrypted with a known key\" },\n"
"        \"off_grid\":  { \"type\": \"integer\", \"description\": \"cumulative off-grid LoRa-shaped peaks; only emitted when scanner is enabled\" }\n"
"      }\n"
"    },\n"
"    \"OffGridEvent\": {\n"
"      \"type\": \"object\",\n"
"      \"description\": \"Off-grid LoRa-shaped energy detected by the scanner.\",\n"
"      \"required\": [\"event\", \"f_hz\", \"snr_db\"],\n"
"      \"properties\": {\n"
"        \"event\":           { \"const\": \"OFF_GRID_LORA\" },\n"
"        \"f_hz\":            { \"type\": \"integer\", \"description\": \"estimated carrier frequency in Hz\" },\n"
"        \"snr_db\":          { \"type\": \"number\" },\n"
"        \"bw_estimate_hz\":  { \"type\": \"number\", \"description\": \"-10 dB skirt-width estimate; gated to >= 50 kHz before alerting\" }\n"
"      }\n"
"    },\n"
"    \"ReplayEvent\": {\n"
"      \"type\": \"object\",\n"
"      \"description\": \"A (from, packet_id) pair seen again > 10 s after first sighting -- past the normal mesh retransmit window.\",\n"
"      \"required\": [\"event\", \"from\", \"packet_id\", \"delta_s\"],\n"
"      \"properties\": {\n"
"        \"event\":     { \"const\": \"REPLAY_SUSPECTED\" },\n"
"        \"from\":      { \"type\": \"string\", \"pattern\": \"^![0-9a-f]{8}$\" },\n"
"        \"packet_id\": { \"type\": \"integer\" },\n"
"        \"delta_s\":   { \"type\": \"number\", \"description\": \"seconds since first sighting of this (from, packet_id)\" }\n"
"      }\n"
"    }\n"
"  }\n"
"}\n";
    return SCHEMA;
}

void schema_print(void)
{
    fputs(schema_json_text(), stdout);
}
