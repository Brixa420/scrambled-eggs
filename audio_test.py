"""Simple audio test script."""
import sounddevice as sd
import numpy as np

def test_microphone():
    print("Testing microphone...")
    print("Available input devices:")
    for i, dev in enumerate(sd.query_devices()):
        if dev['max_input_channels'] > 0:
            print(f"  {i}: {dev['name']} (in: {dev['max_input_channels']} channels)")
    
    # Use default input device
    duration = 3  # seconds
    sample_rate = 16000
    
    print(f"\nRecording for {duration} seconds... (speak into your microphone)")
    
    def callback(indata, frames, time, status):
        if status:
            print(f"Status: {status}")
        volume_norm = np.linalg.norm(indata) * 10
        print(f"Volume: {int(volume_norm)}/100", end='\r')
    
    with sd.InputStream(callback=callback, channels=1, samplerate=sample_rate):
        sd.sleep(int(duration * 1000))
    
    print("\nTest complete!")

if __name__ == "__main__":
    test_microphone()
