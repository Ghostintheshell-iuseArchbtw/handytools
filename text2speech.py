import os
import re
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
from typing import Optional

console = Console()

def text_to_speech(text: str, output_filename: str, lang: str = 'en', slow: bool = False) -> None:
    """Convert text to speech and save as audio file."""
    try:
        tts = gTTS(text=text, lang=lang, slow=slow)
        tts.save(output_filename)
        console.print(f"[green]Success![/] Audio saved to {output_filename}")
    except Exception as e:
        console.print(f"[red]Error during text-to-speech conversion:[/] {e}")
        sys.exit(1)

def generate_sine_wave(frequency: float, duration: float, sample_rate: int = 44100) -> np.ndarray:
    """Generate a sine wave audio signal."""
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    return np.sin(2 * np.pi * frequency * t)

def synthesize_text(text: str) -> tuple[np.ndarray, int]:
    """Convert text to synthesized speech using wave synthesis."""
    sample_rate = 44100
    base_freq = 440  # A4 note
    duration = 0.2
    
    audio_data = np.array([])
    for char in text.lower():
        if char == ' ':
            # Add silence for spaces
            wave_data = np.zeros(int(sample_rate * duration))
        else:
            # Calculate frequency for letters
            freq_mod = (ord(char) - ord('a')) * 20
            freq = base_freq + freq_mod
            wave_data = generate_sine_wave(freq, duration, sample_rate)
        audio_data = np.concatenate([audio_data, wave_data])
    
    return audio_data, sample_rate

def clean_text(text: str) -> Optional[str]:
    """Clean and sanitize input text."""
    # Remove unwanted characters and normalize whitespace
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text if text else None

def process_file(filename: str, use_synth: bool = False) -> None:
    """Process text file and convert contents to speech."""
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            raw_text = file.read()

        # Clean and validate text
        text = clean_text(raw_text)
        if not text:
            console.print("[red]Error:[/] No valid text remaining after cleaning")
            sys.exit(1)

        output_path = Path(filename).with_suffix('.wav' if use_synth else '.mp3')
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if use_synth:
            audio_data, sample_rate = synthesize_text(text)
            with wave.open(str(output_path), 'wb') as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(sample_rate)
                wav_file.writeframes((audio_data * 32767).astype(np.int16).tobytes())
            console.print(f"[green]Success![/] Synthesized audio saved to {output_path}")
        else:
            with console.status("[bold green]Converting text to speech..."):
                text_to_speech(text, str(output_path))
    except Exception as e:
        console.print(f"[red]Error processing file:[/] {e}")
        sys.exit(1)

def live_synth_mode() -> None:
    """Interactive live synthesizer mode."""
    console.print("[yellow]Live Synthesizer Mode - Press ESC to exit[/]")
    console.print("[cyan]Type letters or space to hear sounds...[/]")
    
    while True:
        event = keyboard.read_event(suppress=True)
        if event.event_type == keyboard.KEY_DOWN:
            if event.name == 'esc':
                break
            
            # Process valid characters
            char = None
            if event.name == 'space':
                char = ' '
            elif len(event.name) == 1 and event.name.isalpha():
                char = event.name.lower()
            
            if char:
                audio_data, sample_rate = synthesize_text(char)
                sd.play(audio_data, sample_rate)
                sd.wait()

def main() -> None:
    """Main application entry point."""
    parser = argparse.ArgumentParser(description='Convert text files to speech')
    parser.add_argument('--file', '-f', help='Input text file path')
    parser.add_argument('--synth', '-s', action='store_true', help='Use wave synthesis')
    parser.add_argument('--clipboard', '-c', action='store_true', help='Read from clipboard')
    args = parser.parse_args()

    if args.clipboard:
        try:
            import pyperclip
            text = clean_text(pyperclip.paste())
            if not text:
                console.print("[red]Error:[/] No valid text in clipboard")
                return
            
            temp_file = Path('clipboard_content.txt')
            temp_file.write_text(text, encoding='utf-8')
            process_file(str(temp_file), args.synth)
            temp_file.unlink()
        except Exception as e:
            console.print(f"[red]Clipboard error:[/] {e}")
        return

    if args.file:
        if not Path(args.file).exists():
            console.print(f"[red]Error:[/] File '{args.file}' not found")
            sys.exit(1)
        process_file(args.file, args.synth)
        return

    # Interactive mode
    console.print(Panel.fit(
        Text("Text-to-Speech Converter", style="bold blue"),
        title="Welcome", border_style="blue"
    ))
    
    while True:
        console.print("\n[bold cyan]Options:[/]")
        console.print("1. Convert text file")
        console.print("2. Convert clipboard content")
        console.print("3. Live synthesizer")
        console.print("4. Exit")
        
        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4"], default="1")

        if choice == "1":
            filename = Prompt.ask("Enter file path")
            if not Path(filename).exists():
                console.print("[red]Error:[/] File not found")
                continue
            use_synth = Prompt.ask("Use synthesis? (y/n)", choices=["y", "n"]) == "y"
            process_file(filename, use_synth)

        elif choice == "2":
            try:
                import pyperclip
                text = clean_text(pyperclip.paste())
                if not text:
                    console.print("[red]Error:[/] No valid text in clipboard")
                    continue
                
                temp_file = Path('clipboard_temp.txt')
                temp_file.write_text(text, encoding='utf-8')
                use_synth = Prompt.ask("Use synthesis? (y/n)", choices=["y", "n"]) == "y"
                process_file(str(temp_file), use_synth)
                temp_file.unlink()
            except Exception as e:
                console.print(f"[red]Error:[/] {e}")

        elif choice == "3":
            live_synth_mode()

        elif choice == "4":
            console.print("[green]Goodbye![/]")
            return

if __name__ == "__main__":
    main()
