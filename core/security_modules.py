import os
import re
import math
import binascii
import wave
from collections import Counter
from PIL import Image

try:
    from pydub import AudioSegment
    PYDUB_AVAILABLE = True
except ImportError:
    PYDUB_AVAILABLE = False

# --- STEGANOGRAPHY ENGINE ---
class StegoDrive:
    def encode(self, image_path, secret_text, output_path):
        try:
            # Force RGB mode to remove Alpha channel (RGBA -> RGB)
            img = Image.open(image_path).convert('RGB')
            encoded = img.copy()
            width, height = img.size
            
            secret_text += "#####" # Delimiter
            binary_secret = ''.join(format(ord(char), '08b') for char in secret_text)
            data_len = len(binary_secret)
            
            if data_len > width * height:
                return False, f"Image too small. Needs {data_len} pixels, has {width*height}."

            data_index = 0
            pixels = encoded.load()
            
            for y in range(height):
                for x in range(width):
                    if data_index < data_len:
                        r, g, b = pixels[x, y]
                        new_r = (r & ~1) | int(binary_secret[data_index])
                        data_index += 1
                        pixels[x, y] = (new_r, g, b)
                    else:
                        break
            
            encoded.save(output_path)
            return True, "Data successfully embedded into pixel structure."
        except Exception as e:
            return False, f"Encoding Error: {str(e)}"

    def decode(self, image_path):
        try:
            img = Image.open(image_path).convert('RGB')
            binary_data = ""
            pixels = img.load()
            width, height = img.size
            
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    binary_data += str(r & 1)
            
            all_text = ""
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) < 8: break
                char = chr(int(byte, 2))
                all_text += char
                if all_text.endswith("#####"):
                    return all_text[:-5]
            
            return "[NO HIDDEN DATA DETECTED]"
        except Exception as e:
            return f"Decoding Error: {str(e)}"

    def _convert_to_wav(self, input_path, output_path):
        if not PYDUB_AVAILABLE:
            return False, "pydub library missing. Run: pip install pydub (and ensure ffmpeg is installed)"
        try:
            audio = AudioSegment.from_file(input_path)
            audio.export(output_path, format="wav")
            return True, "Converted successfully"
        except Exception as e:
            return False, f"Audio Conversion error: {str(e)}"

    def encode_audio(self, audio_path, secret_text, output_path):
        """Encodes text into a WAV audio file using LSB. Converts MP3 safely."""
        try:
            process_path = audio_path
            # If MP3, convert to temporary WAV
            if audio_path.lower().endswith('.mp3'):
                temp_wav = audio_path + "_temp.wav"
                success, msg = self._convert_to_wav(audio_path, temp_wav)
                if not success: return False, msg
                process_path = temp_wav

            song = wave.open(process_path, mode='rb')
            frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            
            secret_text += "#####" # Delimiter
            binary_secret = ''.join(format(ord(char), '08b') for char in secret_text)
            
            if len(binary_secret) > len(frame_bytes):
                song.close()
                return False, f"Audio too short. Needs {len(binary_secret)} bytes."

            # Inject the binary data into the LSB of the audio frames
            for i in range(len(binary_secret)):
                frame_bytes[i] = (frame_bytes[i] & ~1) | int(binary_secret[i])
                
            with wave.open(output_path, 'wb') as fd:
                fd.setparams(song.getparams())
                fd.writeframes(frame_bytes)
            song.close()
            
            # Cleanup temp file if we created one
            if process_path != audio_path and os.path.exists(process_path):
                os.remove(process_path)
                
            return True, "Data successfully embedded. Output secured as Lossless WAV to prevent corruption."
        except Exception as e:
            return False, f"Audio Encoding Error: {str(e)}"

    def decode_audio(self, audio_path):
        """Extracts hidden text from an audio file"""
        try:
            process_path = audio_path
            if audio_path.lower().endswith('.mp3'):
                temp_wav = audio_path + "_temp.wav"
                success, msg = self._convert_to_wav(audio_path, temp_wav)
                if not success: return msg
                process_path = temp_wav

            song = wave.open(process_path, mode='rb')
            frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            song.close()
            
            if process_path != audio_path and os.path.exists(process_path):
                os.remove(process_path)
            
            # Extract the LSB from every frame
            extracted = [str(frame_bytes[i] & 1) for i in range(len(frame_bytes))]
            binary_data = "".join(extracted)
            
            all_text = ""
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) < 8: break
                all_text += chr(int(byte, 2))
                if all_text.endswith("#####"):
                    return all_text[:-5]
                    
            return "[NO HIDDEN DATA DETECTED]"
        except Exception as e:
            return f"Audio Decoding Error: {str(e)}"