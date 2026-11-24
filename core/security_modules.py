import os
import re
import math
import binascii
import wave
import uuid
import tempfile
import io
from collections import Counter
from PIL import Image

try:
    from pydub import AudioSegment
    PYDUB_AVAILABLE = True
except ImportError:
    PYDUB_AVAILABLE = False


def _get_temp_filepath(suffix=""):
    """Generates a unique safe path in the writable temp directory."""
    temp_dir = tempfile.gettempdir()
    return os.path.join(temp_dir, f"stego_{uuid.uuid4().hex}{suffix}")


class StegoDrive:
    def encode(self, image_input, secret_text, output_dest=None):
        """
        Embeds secret text into an image using LSB in RGB mode.
        Accepts file paths, file-like objects, or bytes for image_input.
        If output_dest is None, returns (True, message, output_bytes).
        If output_dest is a path, saves to that path and returns (True, message, output_bytes).
        """
        try:
            # Force RGB mode to remove Alpha channel
            img = Image.open(image_input).convert('RGB')
            encoded = img.copy()
            width, height = img.size
            
            secret_text += "#####"  # Delimiter
            binary_secret = ''.join(format(ord(char), '08b') for char in secret_text)
            data_len = len(binary_secret)
            
            if data_len > width * height:
                return False, f"Image too small. Needs {data_len} pixels, has {width*height}.", None

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

            # Export to BytesIO
            byte_arr = io.BytesIO()
            encoded.save(byte_arr, format='PNG')
            output_bytes = byte_arr.getvalue()

            if output_dest:
                if isinstance(output_dest, (str, bytes, os.PathLike)):
                    with open(output_dest, 'wb') as f:
                        f.write(output_bytes)
                elif hasattr(output_dest, 'write'):
                    output_dest.write(output_bytes)

            return True, "Data successfully embedded into pixel structure.", output_bytes
        except Exception as e:
            return False, f"Encoding Error: {str(e)}", None

    def decode(self, image_input):
        """Extracts hidden text from an image (path or file-like object)."""
        try:
            img = Image.open(image_input).convert('RGB')
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
                if len(byte) < 8:
                    break
                char = chr(int(byte, 2))
                all_text += char
                if all_text.endswith("#####"):
                    return all_text[:-5]
            
            return "[NO HIDDEN DATA DETECTED]"
        except Exception as e:
            return f"Decoding Error: {str(e)}"

    def _convert_to_wav(self, input_path, output_path):
        if not PYDUB_AVAILABLE:
            return False, "MP3 processing requires ffmpeg/pydub which is not available in serverless environments. Please upload a lossless .wav file instead."
        try:
            audio = AudioSegment.from_file(input_path)
            audio.export(output_path, format="wav")
            return True, "Converted successfully"
        except Exception as e:
            return False, "MP3 processing requires ffmpeg which is not available in serverless environments. Please upload a lossless .wav file instead."

    def encode_audio(self, audio_input, secret_text, output_dest=None):
        """
        Encodes text into a WAV audio file using LSB.
        Works via Python's built-in wave module in writable temp storage.
        Safely handles MP3 requests with clear serverless guidance when ffmpeg is unavailable.
        """
        temp_files = []
        try:
            # Handle audio input
            if isinstance(audio_input, (str, bytes, os.PathLike)):
                is_mp3 = str(audio_input).lower().endswith('.mp3')
                src_path = audio_input
            else:
                filename = getattr(audio_input, 'filename', '')
                is_mp3 = filename.lower().endswith('.mp3')
                temp_in = _get_temp_filepath('.mp3' if is_mp3 else '.wav')
                temp_files.append(temp_in)
                with open(temp_in, 'wb') as f:
                    if hasattr(audio_input, 'read'):
                        audio_input.seek(0)
                        f.write(audio_input.read())
                    else:
                        f.write(bytes(audio_input))
                src_path = temp_in

            process_path = src_path
            if is_mp3:
                temp_wav = _get_temp_filepath('.wav')
                temp_files.append(temp_wav)
                success, msg = self._convert_to_wav(src_path, temp_wav)
                if not success:
                    return False, msg, None
                process_path = temp_wav

            try:
                song = wave.open(process_path, mode='rb')
            except Exception as e:
                return False, f"Audio File Error: Could not parse WAV stream ({str(e)}). Please ensure it is standard PCM WAV format.", None

            try:
                params = song.getparams()
                frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            finally:
                song.close()
            
            secret_text += "#####"  # Delimiter
            binary_secret = ''.join(format(ord(char), '08b') for char in secret_text)
            
            if len(binary_secret) > len(frame_bytes):
                return False, f"Audio too short. Needs {len(binary_secret)} samples, has {len(frame_bytes)}.", None

            # Inject binary data into LSB of audio frames
            for i in range(len(binary_secret)):
                frame_bytes[i] = (frame_bytes[i] & ~1) | int(binary_secret[i])
                
            temp_out = _get_temp_filepath('.wav')
            temp_files.append(temp_out)
            with wave.open(temp_out, 'wb') as fd:
                fd.setparams(params)
                fd.writeframes(frame_bytes)

            with open(temp_out, 'rb') as f:
                output_bytes = f.read()

            if output_dest:
                if isinstance(output_dest, (str, bytes, os.PathLike)):
                    with open(output_dest, 'wb') as f:
                        f.write(output_bytes)
                elif hasattr(output_dest, 'write'):
                    output_dest.write(output_bytes)

            return True, "Data successfully embedded. Output secured as Lossless WAV.", output_bytes
        except Exception as e:
            return False, f"Audio Encoding Error: {str(e)}", None
        finally:
            for tf in temp_files:
                try:
                    if os.path.exists(tf):
                        os.remove(tf)
                except Exception:
                    pass

    def decode_audio(self, audio_input):
        """Extracts hidden text from an audio file (path or file-like object)."""
        temp_files = []
        try:
            if isinstance(audio_input, (str, bytes, os.PathLike)):
                is_mp3 = str(audio_input).lower().endswith('.mp3')
                src_path = audio_input
            else:
                filename = getattr(audio_input, 'filename', '')
                is_mp3 = filename.lower().endswith('.mp3')
                temp_in = _get_temp_filepath('.mp3' if is_mp3 else '.wav')
                temp_files.append(temp_in)
                with open(temp_in, 'wb') as f:
                    if hasattr(audio_input, 'read'):
                        audio_input.seek(0)
                        f.write(audio_input.read())
                    else:
                        f.write(bytes(audio_input))
                src_path = temp_in

            process_path = src_path
            if is_mp3:
                temp_wav = _get_temp_filepath('.wav')
                temp_files.append(temp_wav)
                success, msg = self._convert_to_wav(src_path, temp_wav)
                if not success:
                    return msg
                process_path = temp_wav

            try:
                song = wave.open(process_path, mode='rb')
            except Exception as e:
                return f"Audio Decoding Error: Could not read WAV ({str(e)}). Please upload a valid PCM .wav file."

            try:
                frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            finally:
                song.close()

            extracted = [str(frame_bytes[i] & 1) for i in range(len(frame_bytes))]
            binary_data = "".join(extracted)
            
            all_text = ""
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) < 8:
                    break
                char = chr(int(byte, 2))
                all_text += char
                if all_text.endswith("#####"):
                    return all_text[:-5]
                    
            return "[NO HIDDEN DATA DETECTED]"
        except Exception as e:
            return f"Audio Decoding Error: {str(e)}"
        finally:
            for tf in temp_files:
                try:
                    if os.path.exists(tf):
                        os.remove(tf)
                except Exception:
                    pass
