#!/usr/bin/env python3
"""
Icon generator for UniFi Analyzer
Creates PNG and ICNS files programmatically using PIL
"""

import os
import subprocess
import tempfile
from PIL import Image, ImageDraw

def create_network_icon(size=512):
    """Create a network connections map icon programmatically"""

    # Create image with blue background
    img = Image.new('RGBA', (size, size), (0, 122, 204, 255))  # Blue background
    draw = ImageDraw.Draw(img)

    # Scale factors for different elements
    scale = size / 512

    # Network nodes (computers/routers)
    nodes = [
        (int(128 * scale), int(128 * scale)),  # Top-left
        (int(384 * scale), int(128 * scale)),  # Top-right
        (int(128 * scale), int(384 * scale)),  # Bottom-left
        (int(384 * scale), int(384 * scale)),  # Bottom-right
        (int(256 * scale), int(256 * scale)),  # Center
    ]

    # Draw connection lines first (behind nodes)
    line_width = int(4 * scale)
    connections = [
        (0, 4), (1, 4), (2, 4), (3, 4),  # Center connections
        (0, 1), (1, 3), (3, 2), (2, 0),  # Outer connections
    ]

    for start_idx, end_idx in connections:
        start_x, start_y = nodes[start_idx]
        end_x, end_y = nodes[end_idx]
        draw.line([start_x, start_y, end_x, end_y], fill='white', width=line_width)

    # Draw network nodes (devices)
    node_size = int(24 * scale)
    for x, y in nodes:
        # Device body
        draw.rectangle([x - node_size, y - node_size, x + node_size, y + node_size],
                       fill='white', outline=(224, 224, 224), width=int(2 * scale))

        # Device screen/monitor
        screen_size = int(16 * scale)
        draw.rectangle([x - screen_size, y - screen_size, x + screen_size, y + screen_size],
                       fill=(51, 51, 51), width=0)

        # Small indicator light
        light_size = int(3 * scale)
        draw.ellipse([x + screen_size - light_size*2, y - screen_size + light_size,
                     x + screen_size - light_size, y - screen_size + light_size*3],
                     fill=(0, 255, 0))

    # Add some network symbols
    # Router symbol in center
    center_x, center_y = nodes[4]
    router_size = int(20 * scale)
    draw.rectangle([center_x - router_size, center_y - router_size,
                   center_x + router_size, center_y + router_size],
                   fill=(255, 255, 255), outline=(224, 224, 224), width=int(2 * scale))

    # Router antennas
    antenna_height = int(16 * scale)
    draw.line([center_x, center_y - router_size, center_x, center_y - router_size - antenna_height],
             fill='white', width=int(2 * scale))

    # Small WiFi waves around center router
    wave_centers = [center_y - router_size - antenna_height - int(8 * scale),
                   center_y - router_size - antenna_height - int(16 * scale)]
    for wave_y in wave_centers:
        # Draw curved wave
        points = []
        for x in range(center_x - int(24 * scale), center_x + int(24 * scale), int(4 * scale)):
            y_offset = int(6 * scale * (1 - abs(x - center_x) / int(24 * scale)))
            points.extend([x, wave_y - y_offset])
        if len(points) >= 4:
            draw.line(points, fill='white', width=int(2 * scale))

    # Add some data flow indicators (small arrows on connections)
    arrow_size = int(6 * scale)
    # Arrow on center-top connection
    arrow_x = nodes[4][0]
    arrow_y = (nodes[0][1] + nodes[4][1]) // 2
    draw.polygon([arrow_x, arrow_y - arrow_size,
                 arrow_x - arrow_size, arrow_y + arrow_size,
                 arrow_x + arrow_size, arrow_y + arrow_size],
                fill='white')

    # Add network cloud symbol in background
    cloud_x = int(64 * scale)
    cloud_y = int(64 * scale)
    cloud_width = int(80 * scale)
    cloud_height = int(40 * scale)

    # Cloud shape using ellipses
    draw.ellipse([cloud_x, cloud_y, cloud_x + cloud_width//2, cloud_y + cloud_height],
                 fill=(255, 255, 255, 128))
    draw.ellipse([cloud_x + cloud_width//4, cloud_y - cloud_height//4,
                 cloud_x + cloud_width*3//4, cloud_y + cloud_height//2],
                 fill=(255, 255, 255, 128))
    draw.ellipse([cloud_x + cloud_width//2, cloud_y, cloud_x + cloud_width, cloud_y + cloud_height],
                 fill=(255, 255, 255, 128))

    return img

def create_icon_files():
    """Generate PNG and ICNS files"""

    png_path = "images/network_icon.png"
    icns_path = "images/network_icon.icns"

    # Create the main icon
    print("Creating network icon...")
    icon_img = create_network_icon(512)
    icon_img.save(png_path, 'PNG')
    print(f"✅ Created {png_path}")

    # Create iconset directory for iconutil
    iconset_dir = tempfile.mkdtemp()
    iconset_name = os.path.join(iconset_dir, "network_icon.iconset")

    print(f"Creating iconset at {iconset_name}")
    os.makedirs(iconset_name)

    # Generate different icon sizes
    sizes = [16, 32, 64, 128, 256, 512]

    for size in sizes:
        # Regular size
        resized = icon_img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(os.path.join(iconset_name, f"icon_{size}x{size}.png"))

        # Retina size (@2x)
        if size <= 256:  # Don't create 512@2x as iconutil might not support it
            retina_size = size * 2
            retina = icon_img.resize((retina_size, retina_size), Image.Resampling.LANCZOS)
            retina.save(os.path.join(iconset_name, f"icon_{size}x{size}@2x.png"))

    # Create ICNS file using iconutil
    print("Creating ICNS file...")
    try:
        result = subprocess.run([
            "iconutil", "-c", "icns", "-o", icns_path, iconset_name
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print(f"✅ Successfully created {icns_path}")
        else:
            print(f"❌ Failed to create ICNS: {result.stderr}")
            return False

    except FileNotFoundError:
        print("❌ iconutil not found. ICNS creation requires macOS.")
        return False

    # Cleanup
    import shutil
    shutil.rmtree(iconset_dir)

    print("✅ Icon generation complete!")
    return True

if __name__ == "__main__":
    create_icon_files()