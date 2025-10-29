#!/usr/bin/env python3
"""
Simple script to create a basic icon for the cybersecurity bot
"""

try:
    from PIL import Image, ImageDraw
    
    def create_icon():
        # Create a 64x64 icon
        size = 64
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw shield background
        shield_points = [
            (32, 8), (48, 16), (48, 32), (32, 56), (16, 32), (16, 16)
        ]
        draw.polygon(shield_points, fill=(0, 212, 255, 255))  # Blue shield
        
        # Draw shield border
        draw.polygon(shield_points, outline=(255, 255, 255, 255), width=2)
        
        # Draw checkmark
        check_points = [(24, 28), (28, 32), (40, 20)]
        draw.line(check_points, fill=(255, 255, 255, 255), width=3)
        
        # Save as ICO
        img.save('icon.ico', format='ICO', sizes=[(64, 64), (32, 32), (16, 16)])
        print("✅ Icon created successfully!")
        
    if __name__ == "__main__":
        create_icon()
        
except ImportError:
    print("❌ PIL (Pillow) not installed. Skipping icon creation...")
    print("💡 To create a proper icon, install Pillow: pip install Pillow")
