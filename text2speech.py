import os
from gtts import gTTS
import sys
from pathlib import Path
import argparse
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
import sounddevice as sd
import numpy as np
import wave
import keyboard

console = Console()

def text_to_speech(text, output_filename, lang='en', slow=False):
    """Convert text to speech and save as audio file.
    
    Args:
        text (str): Text to convert to speech
        output_filename (str): Path to save the audio file
        lang (str): Language code for speech (default: 'en')
        slow (bool): Whether to speak slowly (default: False)
    """
    try:
        tts = gTTS(text=text, lang=lang, slow=slow)
        tts.save(output_filename)
        console.print(f"[green]Success![/] Converted text saved to {output_filename}")
    except Exception as e:
        console.print(f"[red]Error during text-to-speech conversion:[/] {e}")
        sys.exit(1)

def generate_sine_wave(frequency, duration, sample_rate=44100):
    """Generate a sine wave audio signal.
    
    Args:
        frequency (float): Frequency in Hz
        duration (float): Duration in seconds
        sample_rate (int): Sample rate in Hz
    """
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    return np.sin(2 * np.pi * frequency * t)

def synthesize_text(text):
    """Convert text to synthesized speech using basic wave synthesis.
    
    Args:
        text (str): Text to synthesize
    """
    sample_rate = 44100
    base_freq = 440  # A4 note
    duration = 0.2
    
    # Generate different tones for different characters
    audio_data = np.array([])
    for char in text.lower():
        # Modify frequency based on character
        freq_mod = (ord(char) - ord('a')) * 20 if char.isalpha() else base_freq
        freq = base_freq + freq_mod
        wave_data = generate_sine_wave(freq, duration, sample_rate)
        audio_data = np.concatenate([audio_data, wave_data])
    
    return audio_data, sample_rate

def process_file(filename, use_synth=False):
    """Process text file and convert contents to speech.
    
    Args:
        filename (str): Path to input text file
        use_synth (bool): Whether to use wave synthesis instead of gTTS
    """
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            text = file.read()

        # Clean the text
        text = ' '.join(text.split())

        if use_synth:
            audio_data, sample_rate = synthesize_text(text)
            output_path = Path(filename).with_suffix('.wav')
            with wave.open(str(output_path), 'wb') as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(sample_rate)
                wav_file.writeframes((audio_data * 32767).astype(np.int16).tobytes())
            console.print(f"[green]Success![/] Synthesized audio saved to {output_path}")
        else:
            output_path = Path(filename).with_suffix('.mp3')
            with console.status("[bold green]Converting text to speech...[/]"):
                text_to_speech(text, str(output_path))
    except Exception as e:
        console.print(f"[red]Error processing the file:[/] {e}")
        sys.exit(1)

def main():
    # Set up argument parser for command line usage
    parser = argparse.ArgumentParser(description='Convert text files to speech')
    parser.add_argument('--file', '-f', help='Input text file path')
    parser.add_argument('--synth', '-s', action='store_true', help='Use wave synthesis instead of gTTS')
    parser.add_argument('--clipboard', '-c', action='store_true', help='Read text from clipboard')
    args = parser.parse_args()

    if args.clipboard:
        import pyperclip
        text = pyperclip.paste()
        temp_file = Path('clipboard_text.txt')
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(text)
        process_file(str(temp_file), args.synth)
        os.remove(temp_file)
        return

    if args.file:
        if not os.path.exists(args.file):
            console.print(f"[red]Error:[/] The file '{args.file}' does not exist.")
            sys.exit(1)
        process_file(args.file, args.synth)
        return

    console.print(Panel.fit(
        Text("Text-to-Speech Converter", style="bold blue"),
        title="Welcome",
        border_style="blue"
    ))
    
    while True:
        console.print("\n[bold cyan]Available Options:[/]")
        console.print("1. Convert text from file")
        console.print("2. Convert text from clipboard")
        console.print("3. Live synthesizer mode")
        console.print("4. Quit")
        
        choice = Prompt.ask("\nEnter your choice", choices=["1", "2", "3", "4"], default="1")

        if choice == "1":
            filename = Prompt.ask("Enter the filename (use a full path if necessary)")
            use_synth = Prompt.ask("Use wave synthesis? (y/n)", choices=["y", "n"], default="n") == "y"
            
            if not os.path.exists(filename):
                console.print(f"[red]Error:[/] The file '{filename}' does not exist.")
                continue
            
            console.print("[yellow]Processing... Please wait.[/]")
            process_file(filename, use_synth)
        
        elif choice == "2":
            import pyperclip
            text = pyperclip.paste()
            temp_file = Path('clipboard_text.txt')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(text)
            use_synth = Prompt.ask("Use wave synthesis? (y/n)", choices=["y", "n"], default="n") == "y"
            process_file(str(temp_file), use_synth)
            os.remove(temp_file)

        elif choice == "3":
            console.print("[yellow]Live Synthesizer Mode - Press ESC to exit[/]")
            console.print("[cyan]Type to hear synthesized sounds...[/]")
            
            while True:
                if keyboard.is_pressed('esc'):
                    break
                
                if keyboard.read_event(suppress=True).event_type == keyboard.KEY_DOWN:
                    char = keyboard.read_event(suppress=True).name
                    if len(char) == 1:
                        audio_data, sample_rate = synthesize_text(char)
                        sd.play(audio_data, sample_rate)
                        sd.wait()

        elif choice == "4":
            console.print("[green]Goodbye![/]")
            break

if __name__ == "__main__":
    main()
