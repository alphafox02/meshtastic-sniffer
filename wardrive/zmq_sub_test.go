// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC

package main

import (
	"testing"
)

func TestEventToObservation_FrameEvent(t *testing.T) {
	js := `{"from":"!433c0b98","packet_id":1234,"channel_hash":126,"channel_name":"LongFast","preset":"LongFast","bw_hz":250000,"freq_hz":906875000,"rssi_db":-65.5,"snr_db":12.3,"decrypted":true,"port_name":"TEXT_MESSAGE_APP","payload_crc_ok":true,"hop_limit":3,"hop_start":3,"long_name":"Alpha","short_name":"AL","hw_model":32,"role":2}`
	ev, err := snifferEventFromString(js)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gps := GPSFix{Valid: true, Lat: 47.61, Lon: -122.33, AltM: 65, SpeedMps: 12, HeadingDeg: 90, Sats: 11}
	o, ok := EventToObservation(&ev, gps)
	if !ok {
		t.Fatalf("EventToObservation returned ok=false on a frame event")
	}
	if o.NodeID != "!433c0b98" {
		t.Errorf("NodeID=%q want !433c0b98", o.NodeID)
	}
	if o.PacketID != 1234 {
		t.Errorf("PacketID=%d want 1234", o.PacketID)
	}
	if o.ChannelHash != 126 {
		t.Errorf("ChannelHash=%d want 126 (0x7e)", o.ChannelHash)
	}
	if !o.Decrypted {
		t.Errorf("Decrypted=false want true")
	}
	if o.PayloadCRCOk == nil || !*o.PayloadCRCOk {
		t.Errorf("PayloadCRCOk lost")
	}
	if o.RxLat != 47.61 || o.RxLon != -122.33 {
		t.Errorf("GPS tagging didn't propagate: Rx=(%v,%v)", o.RxLat, o.RxLon)
	}
	if o.LongName != "Alpha" || o.HWModel != 32 {
		t.Errorf("NodeInfo fields lost: long=%q hw=%d", o.LongName, o.HWModel)
	}
}

func TestEventToObservation_DropsDiscriminatorEvents(t *testing.T) {
	cases := []string{
		`{"event":"STATS","msps":18.4,"frames":42,"decrypted":30}`,
		`{"event":"OFF_GRID_LORA","freq_hz":906500000}`,
		`{"event":"REPLAY_SUSPECTED","from":"!aaaa"}`,
		`{"event":"GEOLOCATED","lat":47.6,"lon":-122.3}`,
		`{"event":"TX","from":"!aaaa","packet_id":1234}`,
	}
	for _, js := range cases {
		ev, _ := snifferEventFromString(js)
		if _, ok := EventToObservation(&ev, GPSFix{}); ok {
			t.Errorf("discriminator event survived: %s", js)
		}
	}
}

func TestEventToObservation_DropsFrameWithoutFrom(t *testing.T) {
	ev, _ := snifferEventFromString(`{"packet_id":1234,"rssi_db":-70}`)
	if _, ok := EventToObservation(&ev, GPSFix{}); ok {
		t.Errorf("frame without 'from' should be dropped")
	}
}

func TestEventToObservation_PositionAppPromotesToSelfReported(t *testing.T) {
	js := `{"from":"!471c1b98","packet_id":99,"channel_name":"MyChan","decrypted":true,"port_name":"POSITION_APP","latitude":47.6099,"longitude":-122.3345,"altitude":42}`
	ev, _ := snifferEventFromString(js)
	o, ok := EventToObservation(&ev, GPSFix{})
	if !ok {
		t.Fatalf("ok=false on POSITION_APP frame")
	}
	if o.SelfReportedLat != 47.6099 || o.SelfReportedLon != -122.3345 {
		t.Errorf("selfrep=(%v,%v) want (47.6099,-122.3345)", o.SelfReportedLat, o.SelfReportedLon)
	}
	if o.SelfReportedAltM != 42 {
		t.Errorf("selfrep_alt=%v want 42", o.SelfReportedAltM)
	}
}

func TestEventToObservation_NoGPSFixWorksGracefully(t *testing.T) {
	ev, _ := snifferEventFromString(`{"from":"!aaaa","packet_id":1,"rssi_db":-70,"channel_hash":1}`)
	o, ok := EventToObservation(&ev, GPSFix{}) // Valid=false
	if !ok {
		t.Fatalf("frame should still produce observation without GPS")
	}
	if o.RxLat != 0 || o.RxLon != 0 {
		t.Errorf("expected 0,0 with no GPS; got (%v,%v)", o.RxLat, o.RxLon)
	}
}
