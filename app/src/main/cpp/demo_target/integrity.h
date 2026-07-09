#pragma once

extern "C" {

__attribute__((visibility("hidden"))) void integrity_capture_baseline();
__attribute__((visibility("hidden"))) bool integrity_text_check();
__attribute__((visibility("hidden"))) bool integrity_maps_check();
__attribute__((visibility("hidden"))) void integrity_crash();

}
