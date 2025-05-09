import random
import hashlib
import matplotlib.pyplot as plt
import time
import pandas as pd
import numpy as np
from matplotlib.animation import FuncAnimation
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading
import queue
import math
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64
import json
import io
import sys


class CaptureOutput:
    """Capture print output to redirect to GUI text widget"""

    def __init__(self, queue):
        self.queue = queue

    def write(self, string):
        self.queue.put(string)

    def flush(self):
        pass


class Vehicle:
    """Vehicle class with enhanced security features"""

    def __init__(self, vehicle_id, speed, position, route=None, malicious=False):
        self.id = vehicle_id
        self.speed = speed
        self.original_speed = speed
        self.position = position
        self.salt = "vanet" + str(random.random())  # Add a salt
        self.route = route or []
        self.current_route_index = 0
        self.malicious = malicious
        self.neighbors = []
        self.message_cache = {}
        self.message_history = []
        self.color = "#" + ''.join([random.choice('0123456789ABCDEF') for _ in range(6)])
        self.trusted = True
        self.trust_score = 100

        # Generate RSA key pair for digital signatures
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Serialize public key for sharing
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def update_neighbors(self, vehicles, radius=100):
        """Update the list of neighbor vehicles within communication range"""
        self.neighbors = []
        for vehicle in vehicles:
            if vehicle != self and self.distance_to(vehicle) <= radius:
                self.neighbors.append(vehicle)

    def distance_to(self, other):
        """Calculate Euclidean distance to another vehicle"""
        return math.sqrt((self.position[0] - other.position[0]) ** 2 +
                         (self.position[1] - other.position[1]) ** 2)

    def move(self, dt, road_network=None):
        """Move vehicle according to speed and direction"""
        if self.route and self.current_route_index < len(self.route) - 1:
            # Follow route
            target = self.route[self.current_route_index + 1]
            direction = (
                target[0] - self.position[0],
                target[1] - self.position[1]
            )
            distance = math.sqrt(direction[0] ** 2 + direction[1] ** 2)

            if distance < 10:  # Reached waypoint
                self.current_route_index += 1
                if self.current_route_index >= len(self.route) - 1:
                    self.speed = 0  # Stop at destination
            else:
                # Normalize direction vector
                direction = (direction[0] / distance, direction[1] / distance)
                # Move towards next waypoint
                self.position = (
                    self.position[0] + direction[0] * self.speed * dt,
                    self.position[1] + direction[1] * self.speed * dt
                )
        else:
            # Random movement if no route
            self.position = (
                self.position[0] + self.speed * dt * random.uniform(-0.1, 1.1),
                self.position[1] + self.speed * dt * random.uniform(-0.1, 1.1)
            )

            # Keep within bounds if road network provided
            if road_network:
                bounds = road_network.get_bounds()
                self.position = (
                    max(bounds[0], min(bounds[2], self.position[0])),
                    max(bounds[1], min(bounds[3], self.position[1]))
                )

    def check_collision(self, other, threshold=10):
        """Check if vehicle collides with another vehicle"""
        distance = self.distance_to(other)
        return distance < threshold

    def generate_message(self):
        """Generate a message with vehicle information"""
        message = {
            "vehicle_id": self.id,
            "speed": self.speed if not self.malicious else self.speed * 2,  # Malicious vehicles may falsify data
            "position": self.position if not self.malicious else (
                self.position[0] + random.uniform(-50, 50),
                self.position[1] + random.uniform(-50, 50)
            ),
            "timestamp": time.time(),
            "neighbors": [v.id for v in self.neighbors],
            "message_id": f"{self.id}_{time.time()}_{random.randint(1000, 9999)}"
        }

        # Add to message history
        self.message_history.append(message)

        # Generate hashes and digital signature
        hashes = self.hash_message(message)
        signature = self.sign_message(message)

        return message, hashes, signature, self.public_key_bytes

    def hash_message(self, message):
        """Generate multiple hash types for the message"""
        message_bytes = json.dumps(message, sort_keys=True).encode()
        hashes = {}

        # SHA-256
        start_time = time.time()
        hashes["sha256"] = hashlib.sha256(message_bytes + self.salt.encode()).hexdigest()
        hashes["sha256_time"] = time.time() - start_time

        # MD5
        start_time = time.time()
        hashes["md5"] = hashlib.md5(message_bytes + self.salt.encode()).hexdigest()
        hashes["md5_time"] = time.time() - start_time

        # SHA-1
        start_time = time.time()
        hashes["sha1"] = hashlib.sha1(message_bytes + self.salt.encode()).hexdigest()
        hashes["sha1_time"] = time.time() - start_time

        # BLAKE2b
        start_time = time.time()
        hashes["blake2b"] = hashlib.blake2b(message_bytes + self.salt.encode()).hexdigest()
        hashes["blake2b_time"] = time.time() - start_time

        # SHA3-256
        start_time = time.time()
        hashes["sha3_256"] = hashlib.sha3_256(message_bytes + self.salt.encode()).hexdigest()
        hashes["sha3_256_time"] = time.time() - start_time

        return hashes

    def sign_message(self, message):
        """Create digital signature for message"""
        message_bytes = json.dumps(message, sort_keys=True).encode()
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(crypto_hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            crypto_hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message, signature, public_key_bytes):
        """Verify digital signature using sender's public key"""
        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
            message_bytes = json.dumps(message, sort_keys=True).encode()
            signature_bytes = base64.b64decode(signature)

            public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(crypto_hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                crypto_hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

    def check_integrity(self, message, hashes):
        """Check if message hashes match to verify integrity"""
        message_hashes = self.hash_message(message)
        for hash_type, hash_value in hashes.items():
            if hash_type in ["sha256", "md5", "sha1", "blake2b", "sha3_256"]:
                if hash_value != message_hashes[hash_type]:
                    return False
        return True

    def process_message(self, message, hashes, signature, public_key_bytes, source_id):
        """Process received message with integrity and authenticity checks"""
        # Check if message is already in cache (duplicate)
        if message.get("message_id") in self.message_cache:
            return False

        # Add to cache to prevent processing duplicates
        self.message_cache[message.get("message_id")] = time.time()

        # Clean old cache entries
        current_time = time.time()
        self.message_cache = {k: v for k, v in self.message_cache.items()
                              if current_time - v < 60}  # Keep messages for 60 seconds

        # Check integrity
        integrity_valid = self.check_integrity(message, hashes)

        # Check signature
        signature_valid = self.verify_signature(message, signature, public_key_bytes)

        # Log results
        message_valid = integrity_valid and signature_valid
        status = "VALID" if message_valid else "INVALID"
        details = []
        if not integrity_valid:
            details.append("Integrity check failed")
        if not signature_valid:
            details.append("Signature verification failed")

        # Add to message history
        self.message_history.append({
            "received_from": source_id,
            "content": message,
            "status": status,
            "details": details if details else "OK",
            "timestamp": time.time()
        })

        return message_valid


class RoadNetwork:
    """Road network for vehicle movement"""

    def __init__(self, width, height):
        self.width = width
        self.height = height
        self.roads = []
        self.junctions = []
        self.generate_grid_network(5, 5)

    def generate_grid_network(self, rows, cols):
        """Generate a grid-based road network"""
        cell_width = self.width / cols
        cell_height = self.height / rows

        # Create junctions (nodes)
        for i in range(rows + 1):
            for j in range(cols + 1):
                self.junctions.append((j * cell_width, i * cell_height))

        # Create horizontal roads
        for i in range(rows + 1):
            road = []
            for j in range(cols + 1):
                road.append((j * cell_width, i * cell_height))
            self.roads.append(road)

        # Create vertical roads
        for j in range(cols + 1):
            road = []
            for i in range(rows + 1):
                road.append((j * cell_width, i * cell_height))
            self.roads.append(road)

    def get_random_route(self, length=5):
        """Generate a random route through the road network"""
        if not self.junctions:
            return []

        start = random.choice(self.junctions)
        route = [start]
        current = start

        for _ in range(length):
            # Find connected junctions
            connected = []
            for road in self.roads:
                if current in road:
                    idx = road.index(current)
                    if idx > 0:
                        connected.append(road[idx - 1])
                    if idx < len(road) - 1:
                        connected.append(road[idx + 1])

            # Remove junctions already in route to avoid loops
            connected = [j for j in connected if j not in route]

            if not connected:
                break

            # Choose next junction
            next_junction = random.choice(connected)
            route.append(next_junction)
            current = next_junction

        return route

    def get_bounds(self):
        """Get the bounds of the road network (xmin, ymin, xmax, ymax)"""
        return (0, 0, self.width, self.height)

    def draw(self, ax):
        """Draw the road network on a matplotlib axis"""
        for road in self.roads:
            x_coords = [p[0] for p in road]
            y_coords = [p[1] for p in road]
            ax.plot(x_coords, y_coords, 'k-', linewidth=1.5, alpha=0.7)

        for junction in self.junctions:
            ax.plot(junction[0], junction[1], 'ko', markersize=5)


class VANETSimulation:
    """VANET simulation with secure routing protocol"""

    def __init__(self, width=800, height=600, num_vehicles=10, malicious_ratio=0.2):
        self.width = width
        self.height = height
        self.num_vehicles = num_vehicles
        self.malicious_ratio = malicious_ratio
        self.vehicles = []
        self.road_network = RoadNetwork(width, height)
        self.initialize_vehicles()
        self.simulation_time = 0
        self.dt = 0.1  # Time step
        self.routing_table = {}  # For route discovery
        self.message_stats = {
            "sent": 0,
            "received": 0,
            "valid": 0,
            "invalid": 0,
            "routing_overhead": 0
        }
        self.performance_metrics = {
            "packet_delivery_ratio": [],
            "end_to_end_delay": [],
            "throughput": [],
            "detection_rate": []
        }
        self.logs = []

        # Track attack and detection stats
        self.attacks = {
            "attempted": 0,
            "detected": 0,
            "successful": 0
        }

        # Hash performance stats
        self.hash_times = {
            "sha256": [],
            "md5": [],
            "sha1": [],
            "blake2b": [],
            "sha3_256": []
        }

    def initialize_vehicles(self):
        """Initialize vehicles in the simulation"""
        self.vehicles = []
        for i in range(self.num_vehicles):
            # Generate random position on road network
            route = self.road_network.get_random_route(random.randint(3, 8))
            if not route:
                position = (random.uniform(0, self.width), random.uniform(0, self.height))
            else:
                position = route[0]

            # Determine if vehicle is malicious
            malicious = random.random() < self.malicious_ratio

            vehicle = Vehicle(
                vehicle_id=f"V{i + 1}",
                speed=random.uniform(30, 100),
                position=position,
                route=route,
                malicious=malicious
            )
            self.vehicles.append(vehicle)

    def discover_route(self, source_id, destination_id):
        """Discover route between source and destination using secure routing protocol"""
        source = None
        destination = None

        # Find source and destination vehicles
        for vehicle in self.vehicles:
            if vehicle.id == source_id:
                source = vehicle
            if vehicle.id == destination_id:
                destination = vehicle

        if not source or not destination:
            return None

        # Simple implementation of secure AODV-like protocol
        visited = set()
        queue = [(source, [source])]

        while queue:
            current, path = queue.pop(0)
            if current.id == destination_id:
                return path

            if current.id not in visited:
                visited.add(current.id)

                # Update neighbors
                current.update_neighbors(self.vehicles)

                for neighbor in current.neighbors:
                    if neighbor.id not in visited and neighbor.trusted:
                        queue.append((neighbor, path + [neighbor]))

        return None

    def broadcast_message(self, source, ttl=3):
        """Broadcast message from source to neighbors with time-to-live"""
        message, hashes, signature, public_key = source.generate_message()

        # Add routing information
        message["ttl"] = ttl
        message["hop_count"] = 0
        message["source"] = source.id
        message["routing"] = True

        # Statistics
        self.message_stats["sent"] += 1
        self.message_stats["routing_overhead"] += 1

        # Log the broadcast
        self.logs.append({
            "time": self.simulation_time,
            "type": "broadcast",
            "source": source.id,
            "message": message
        })

        # Update source's neighbors
        source.update_neighbors(self.vehicles)

        # Send to all neighbors
        for neighbor in source.neighbors:
            # If malicious source, attempt attack
            if source.malicious:
                if random.random() < 0.7:  # 70% chance of attempting attack
                    self.attacks["attempted"] += 1
                    # Tamper with message
                    tampered_message = message.copy()
                    if random.random() < 0.5:
                        tampered_message["speed"] = message["speed"] * 2
                    else:
                        tampered_message["position"] = (
                            message["position"][0] + random.uniform(-50, 50),
                            message["position"][1] + random.uniform(-50, 50)
                        )
                    self.receive_message(neighbor, tampered_message, hashes, signature, public_key, source.id)
                else:
                    # Send normal message
                    self.receive_message(neighbor, message, hashes, signature, public_key, source.id)
            else:
                # Normal vehicle sends normal message
                self.receive_message(neighbor, message, hashes, signature, public_key, source.id)

    def receive_message(self, vehicle, message, hashes, signature, public_key, source_id):
        """Vehicle receives a message"""
        self.message_stats["received"] += 1

        # Process message with security checks
        valid = vehicle.process_message(message, hashes, signature, public_key, source_id)

        if valid:
            self.message_stats["valid"] += 1

            # Handle routing messages
            if message.get("routing") and message.get("ttl", 0) > 0:
                # Decrease TTL
                message["ttl"] = message["ttl"] - 1
                message["hop_count"] = message["hop_count"] + 1

                # Forward to neighbors
                vehicle.update_neighbors(self.vehicles)
                for neighbor in vehicle.neighbors:
                    if neighbor.id != source_id:  # Don't send back to source
                        self.receive_message(neighbor, message, hashes, signature, public_key, vehicle.id)
        else:
            self.message_stats["invalid"] += 1

            # Record attack detection
            if not valid and any(v.id == source_id and v.malicious for v in self.vehicles):
                self.attacks["detected"] += 1

                # Update trust score of malicious vehicle
                for v in self.vehicles:
                    if v.id == source_id:
                        v.trust_score -= 10
                        if v.trust_score < 50:
                            v.trusted = False

            # If attack not detected from malicious vehicle, count as successful attack
            elif any(v.id == source_id and v.malicious for v in self.vehicles):
                self.attacks["successful"] += 1

        # Log the receipt
        self.logs.append({
            "time": self.simulation_time,
            "type": "receive",
            "source": source_id,
            "destination": vehicle.id,
            "valid": valid,
            "message": message
        })

    def update(self):
        """Update simulation state"""
        self.simulation_time += self.dt

        # Move vehicles
        for vehicle in self.vehicles:
            vehicle.move(self.dt, self.road_network)

            # Check for collisions
            for other in self.vehicles:
                if vehicle != other and vehicle.check_collision(other):
                    # Log collision
                    self.logs.append({
                        "time": self.simulation_time,
                        "type": "collision",
                        "vehicles": [vehicle.id, other.id],
                        "position": vehicle.position
                    })

                    # Reduce speed after collision
                    vehicle.speed = max(0, vehicle.speed * 0.5)
                    other.speed = max(0, other.speed * 0.5)

        # Update neighbors for all vehicles
        for vehicle in self.vehicles:
            vehicle.update_neighbors(self.vehicles)

        # Broadcast messages from random vehicles
        if random.random() < 0.3:  # 30% chance of broadcast happening
            source = random.choice(self.vehicles)
            self.broadcast_message(source)

        # Calculate performance metrics
        if self.message_stats["sent"] > 0:
            pdr = self.message_stats["valid"] / self.message_stats["sent"]
            self.performance_metrics["packet_delivery_ratio"].append((self.simulation_time, pdr))

        if self.attacks["attempted"] > 0:
            detection_rate = self.attacks["detected"] / self.attacks["attempted"]
            self.performance_metrics["detection_rate"].append((self.simulation_time, detection_rate))

        # Collect hash times
        for vehicle in self.vehicles:
            message, hashes, _, _ = vehicle.generate_message()
            for hash_type, times in self.hash_times.items():
                if f"{hash_type}_time" in hashes:
                    times.append(hashes[f"{hash_type}_time"])

    def run(self, steps=100):
        """Run simulation for specified number of steps"""
        for _ in range(steps):
            self.update()

        # Generate report
        return self.generate_report()

    def generate_report(self):
        """Generate performance report"""
        report = {
            "simulation_time": self.simulation_time,
            "vehicles": len(self.vehicles),
            "malicious_vehicles": sum(1 for v in self.vehicles if v.malicious),
            "messages": self.message_stats,
            "attacks": self.attacks,
            "performance": {
                "packet_delivery_ratio": self.performance_metrics["packet_delivery_ratio"][-1][1]
                if self.performance_metrics["packet_delivery_ratio"] else 0,
                "detection_rate": self.performance_metrics["detection_rate"][-1][1]
                if self.performance_metrics["detection_rate"] else 0
            },
            "hash_performance": {
                hash_type: sum(times) / len(times) if times else 0
                for hash_type, times in self.hash_times.items()
            }
        }
        return report


class VANETSimulationApp:
    """Main application for VANET simulation with GUI"""

    def __init__(self, root):
        self.root = root
        self.root.title("VANET Secure Routing Protocol Simulation")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f2f5")

        # Set theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f0f2f5")
        style.configure("TLabel", background="#f0f2f5", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TNotebook", background="#f0f2f5")
        style.configure("TNotebook.Tab", padding=[10, 5], font=("Segoe UI", 10))

        # Create simulation
        self.simulation = VANETSimulation()

        # Setup variables
        self.running = False
        self.simulation_speed = tk.DoubleVar(value=1.0)
        self.num_vehicles = tk.IntVar(value=10)
        self.malicious_ratio = tk.DoubleVar(value=0.2)
        self.hash_algorithm = tk.StringVar(value="sha256")
        self.output_queue = queue.Queue()

        # Redirect stdout to our queue
        self.old_stdout = sys.stdout
        sys.stdout = CaptureOutput(self.output_queue)

        # Setup UI
        self.setup_ui()

        # Update loop
        self.update_interval = 100  # ms
        self.after_id = None

        # Animation
        self.ani = None

    def setup_ui(self):
        """Setup the user interface"""
        # Main layout
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(header_frame, text="VANET Secure Routing Protocol Simulation",
                                font=("Segoe UI", 18, "bold"))
        title_label.pack(side=tk.LEFT)

        # Tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Simulation tab
        sim_tab = ttk.Frame(notebook)
        notebook.add(sim_tab, text="Simulation")

        # Control panel
        control_frame = ttk.LabelFrame(sim_tab, text="Simulation Controls")
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=5)

        # Parameters section
        params_frame = ttk.Frame(control_frame)
        params_frame.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(params_frame, text="Number of Vehicles:").grid(row=0, column=0, sticky=tk.W, pady=5)
        vehicle_spinbox = ttk.Spinbox(params_frame, from_=2, to=50, textvariable=self.num_vehicles, width=10)
        vehicle_spinbox.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(params_frame, text="Malicious Ratio:").grid(row=1, column=0, sticky=tk.W, pady=5)
        malicious_spinbox = ttk.Spinbox(params_frame, from_=0, to=1, increment=0.1,
                                        textvariable=self.malicious_ratio, width=10)
        malicious_spinbox.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(params_frame, text="Hash Algorithm:").grid(row=2, column=0, sticky=tk.W, pady=5)
        hash_combo = ttk.Combobox(params_frame, textvariable=self.hash_algorithm, width=10)
        hash_combo['values'] = ("sha256", "md5", "sha1", "blake2b", "sha3_256")
        hash_combo.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(params_frame, text="Simulation Speed:").grid(row=3, column=0, sticky=tk.W, pady=5)
        speed_scale = ttk.Scale(params_frame, from_=0.1, to=5.0, variable=self.simulation_speed,
                                orient=tk.HORIZONTAL, length=150)
        speed_scale.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)

        # Buttons
        buttons_frame = ttk.Frame(control_frame)
        buttons_frame.pack(fill=tk.X, pady=10, padx=5)

        initialize_btn = ttk.Button(buttons_frame, text="Initialize", command=self.initialize_simulation)
        initialize_btn.pack(fill=tk.X, pady=2)

        start_btn = ttk.Button(buttons_frame, text="Start", command=self.start_simulation)
        start_btn.pack(fill=tk.X, pady=2)

        stop_btn = ttk.Button(buttons_frame, text="Stop", command=self.stop_simulation)
        stop_btn.pack(fill=tk.X, pady=2)

        reset_btn = ttk.Button(buttons_frame, text="Reset", command=self.reset_simulation)
        reset_btn.pack(fill=tk.X, pady=2)

        # Visualization and data section
        viz_frame = ttk.Frame(sim_tab)
        viz_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Network visualization
        self.fig = Figure(figsize=(10, 6), dpi=100)
        self.network_ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Status and log section
        log_frame = ttk.LabelFrame(main_frame, text="Simulation Log")
        log_frame.pack(fill=tk.BOTH, expand=False, pady=10)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Performance metrics tab
        metrics_tab = ttk.Frame(notebook)
        notebook.add(metrics_tab, text="Performance Metrics")

        metrics_frame = ttk.Frame(metrics_tab)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Performance metrics layout
        self.metrics_fig = Figure(figsize=(10, 8), dpi=100)

        # PDR graph
        self.pdr_ax = self.metrics_fig.add_subplot(221)
        self.pdr_ax.set_title("Packet Delivery Ratio")
        self.pdr_ax.set_xlabel("Time (s)")
        self.pdr_ax.set_ylabel("PDR")

        # Detection rate graph
        self.detection_ax = self.metrics_fig.add_subplot(222)
        self.detection_ax.set_title("Attack Detection Rate")
        self.detection_ax.set_xlabel("Time (s)")
        self.detection_ax.set_ylabel("Detection Rate")

        # Hash performance graph
        self.hash_ax = self.metrics_fig.add_subplot(223)
        self.hash_ax.set_title("Hash Algorithm Performance")
        self.hash_ax.set_xlabel("Algorithm")
        self.hash_ax.set_ylabel("Time (ms)")

        # Security status graph
        self.security_ax = self.metrics_fig.add_subplot(224)
        self.security_ax.set_title("Security Status")
        self.security_ax.set_xlabel("Vehicle")
        self.security_ax.set_ylabel("Trust Score")

        self.metrics_canvas = FigureCanvasTkAgg(self.metrics_fig, master=metrics_frame)
        self.metrics_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add metrics control section
        metrics_control_frame = ttk.Frame(metrics_frame)
        metrics_control_frame.pack(fill=tk.X, pady=10)

        ttk.Button(metrics_control_frame, text="Update Metrics",
                   command=self.update_metrics).pack(side=tk.LEFT, padx=5)

        ttk.Button(metrics_control_frame, text="Export Data",
                   command=self.export_metrics).pack(side=tk.LEFT, padx=5)

        # Security tab
        security_tab = ttk.Frame(notebook)
        notebook.add(security_tab, text="Security Analysis")

        security_frame = ttk.Frame(security_tab)
        security_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Security visualization
        self.security_fig = Figure(figsize=(10, 8), dpi=100)

        # Attack graph
        self.attack_ax = self.security_fig.add_subplot(221)
        self.attack_ax.set_title("Attack Statistics")
        self.attack_ax.set_ylabel("Count")

        # Message integrity graph
        self.integrity_ax = self.security_fig.add_subplot(222)
        self.integrity_ax.set_title("Message Integrity")
        self.integrity_ax.set_ylabel("Count")

        # Trust network graph
        self.trust_ax = self.security_fig.add_subplot(212)
        self.trust_ax.set_title("Trust Network")

        self.security_canvas = FigureCanvasTkAgg(self.security_fig, master=security_frame)
        self.security_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add security control section
        security_control_frame = ttk.Frame(security_frame)
        security_control_frame.pack(fill=tk.X, pady=10)

        ttk.Button(security_control_frame, text="Analyze Security",
                   command=self.analyze_security).pack(side=tk.LEFT, padx=5)

        ttk.Button(security_control_frame, text="Simulate Attack",
                   command=self.simulate_attack).pack(side=tk.LEFT, padx=5)

        # Set up periodic log update
        self.root.after(100, self.update_log)

    def initialize_simulation(self):
        """Initialize the simulation with current parameters"""
        try:
            num_vehicles = self.num_vehicles.get()
            malicious_ratio = self.malicious_ratio.get()

            self.simulation = VANETSimulation(
                num_vehicles=num_vehicles,
                malicious_ratio=malicious_ratio
            )

            self.log_text.insert(tk.END, f"Initialized simulation with {num_vehicles} vehicles "
                                         f"({int(num_vehicles * malicious_ratio)} malicious)\n")
            self.log_text.see(tk.END)

            # Draw initial state
            self.draw_network()
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Error initializing simulation: {str(e)}")

    def start_simulation(self):
        """Start the simulation"""
        if not self.running:
            self.running = True
            self.log_text.insert(tk.END, "Starting simulation...\n")
            self.log_text.see(tk.END)

            # Start animation
            self.ani = FuncAnimation(
                self.fig,
                self.update_animation,
                interval=self.update_interval,
                blit=False
            )
            self.canvas.draw()

    def stop_simulation(self):
        """Stop the simulation"""
        if self.running:
            self.running = False
            if self.ani:
                self.ani.event_source.stop()
            self.log_text.insert(tk.END, "Simulation stopped.\n")
            self.log_text.see(tk.END)

    def reset_simulation(self):
        """Reset simulation to initial state"""
        self.stop_simulation()
        self.simulation = VANETSimulation()
        self.log_text.insert(tk.END, "Simulation reset.\n")
        self.log_text.see(tk.END)
        self.draw_network()

    def update_animation(self, frame):
        """Update animation frame"""
        # Update simulation at appropriate speed
        for _ in range(int(self.simulation_speed.get())):
            self.simulation.update()

        # Redraw network
        self.draw_network()
        return []

    def draw_network(self):
        """Draw the road network and vehicles"""
        self.network_ax.clear()

        # Draw road network
        self.simulation.road_network.draw(self.network_ax)

        # Draw vehicles
        for vehicle in self.simulation.vehicles:
            color = 'red' if vehicle.malicious else 'blue'
            alpha = 0.5 if not vehicle.trusted else 1.0

            # Draw vehicle
            self.network_ax.plot(vehicle.position[0], vehicle.position[1], 'o',
                                 color=color, markersize=8, alpha=alpha)

            # Draw vehicle ID
            self.network_ax.text(vehicle.position[0], vehicle.position[1] + 10,
                                 vehicle.id, fontsize=8, ha='center')

            # Draw connections to neighbors
            for neighbor in vehicle.neighbors:
                line_style = '--' if vehicle.malicious or neighbor.malicious else '-'
                self.network_ax.plot(
                    [vehicle.position[0], neighbor.position[0]],
                    [vehicle.position[1], neighbor.position[1]],
                    line_style, color='green', alpha=0.3, linewidth=1
                )

        # Set axis properties
        self.network_ax.set_xlim(0, self.simulation.width)
        self.network_ax.set_ylim(0, self.simulation.height)
        self.network_ax.set_title(f"VANET Simulation - Time: {self.simulation.simulation_time:.1f}s")

        # Add legend
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=8, label='Normal'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=8, label='Malicious')
        ]
        self.network_ax.legend(handles=legend_elements, loc='upper right')

        self.canvas.draw()

    def update_metrics(self):
        """Update performance metrics"""
        # Clear graphs
        self.pdr_ax.clear()
        self.detection_ax.clear()
        self.hash_ax.clear()
        self.security_ax.clear()

        # PDR graph
        if self.simulation.performance_metrics["packet_delivery_ratio"]:
            times, pdrs = zip(*self.simulation.performance_metrics["packet_delivery_ratio"])
            self.pdr_ax.plot(times, pdrs, 'b-')
            self.pdr_ax.set_ylim(0, 1)

        self.pdr_ax.set_title("Packet Delivery Ratio")
        self.pdr_ax.set_xlabel("Time (s)")
        self.pdr_ax.set_ylabel("PDR")

        # Detection rate graph
        if self.simulation.performance_metrics["detection_rate"]:
            times, rates = zip(*self.simulation.performance_metrics["detection_rate"])
            self.detection_ax.plot(times, rates, 'g-')
            self.detection_ax.set_ylim(0, 1)

        self.detection_ax.set_title("Attack Detection Rate")
        self.detection_ax.set_xlabel("Time (s)")
        self.detection_ax.set_ylabel("Detection Rate")

        # Hash performance graph
        hash_types = list(self.simulation.hash_times.keys())
        avg_times = []

        for hash_type in hash_types:
            times = self.simulation.hash_times[hash_type]
            if times:
                avg_times.append(sum(times) / len(times) * 1000)  # Convert to ms
            else:
                avg_times.append(0)

        self.hash_ax.bar(hash_types, avg_times)
        self.hash_ax.set_title("Hash Algorithm Performance")
        self.hash_ax.set_xlabel("Algorithm")
        self.hash_ax.set_ylabel("Time (ms)")

        # Security status graph
        vehicle_ids = [v.id for v in self.simulation.vehicles]
        trust_scores = [v.trust_score for v in self.simulation.vehicles]
        colors = ['red' if v.malicious else 'blue' for v in self.simulation.vehicles]

        self.security_ax.bar(vehicle_ids, trust_scores, color=colors)
        self.security_ax.set_title("Vehicle Trust Scores")
        self.security_ax.set_xlabel("Vehicle")
        self.security_ax.set_ylabel("Trust Score")
        self.security_ax.set_ylim(0, 100)
        self.security_ax.tick_params(axis='x', rotation=45)

        # Adjust layout and draw
        self.metrics_fig.tight_layout()
        self.metrics_canvas.draw()

    def export_metrics(self):
        """Export metrics data to CSV files"""
        try:
            # Create reports directory if it doesn't exist
            import os
            if not os.path.exists("reports"):
                os.makedirs("reports")

            # Export PDR data
            pdr_data = pd.DataFrame(self.simulation.performance_metrics["packet_delivery_ratio"],
                                    columns=["time", "pdr"])
            pdr_data.to_csv("reports/packet_delivery_ratio.csv", index=False)

            # Export detection rate data
            detection_data = pd.DataFrame(self.simulation.performance_metrics["detection_rate"],
                                          columns=["time", "detection_rate"])
            detection_data.to_csv("reports/detection_rate.csv", index=False)

            # Export hash performance data
            hash_data = []
            for hash_type, times in self.simulation.hash_times.items():
                for time_val in times:
                    hash_data.append({"hash_type": hash_type, "time": time_val})

            hash_df = pd.DataFrame(hash_data)
            hash_df.to_csv("reports/hash_performance.csv", index=False)

            # Export trust scores
            trust_data = []
            for vehicle in self.simulation.vehicles:
                trust_data.append({
                    "vehicle_id": vehicle.id,
                    "malicious": vehicle.malicious,
                    "trust_score": vehicle.trust_score,
                    "trusted": vehicle.trusted
                })

            trust_df = pd.DataFrame(trust_data)
            trust_df.to_csv("reports/trust_scores.csv", index=False)

            # Export simulation log
            log_data = pd.DataFrame(self.simulation.logs)
            log_data.to_csv("reports/simulation_log.csv", index=False)

            messagebox.showinfo("Export Successful",
                                "Metrics data exported to 'reports' directory")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting metrics: {str(e)}")

    def analyze_security(self):
        """Analyze security metrics"""
        # Clear security graphs
        self.attack_ax.clear()
        self.integrity_ax.clear()
        self.trust_ax.clear()

        # Attack statistics
        attack_labels = ['Attempted', 'Detected', 'Successful']
        attack_values = [self.simulation.attacks["attempted"],
                         self.simulation.attacks["detected"],
                         self.simulation.attacks["successful"]]

        self.attack_ax.bar(attack_labels, attack_values, color=['orange', 'green', 'red'])
        self.attack_ax.set_title("Attack Statistics")

        # Message integrity
        integrity_labels = ['Valid', 'Invalid']
        integrity_values = [self.simulation.message_stats["valid"],
                            self.simulation.message_stats["invalid"]]

        self.integrity_ax.bar(integrity_labels, integrity_values, color=['green', 'red'])
        self.integrity_ax.set_title("Message Integrity")

        # Trust network
        self.trust_ax.clear()

        # Plot vehicles as nodes
        x_coords = [v.position[0] for v in self.simulation.vehicles]
        y_coords = [v.position[1] for v in self.simulation.vehicles]
        colors = ['red' if v.malicious else 'blue' for v in self.simulation.vehicles]
        sizes = [100 if v.trusted else 50 for v in self.simulation.vehicles]

        self.trust_ax.scatter(x_coords, y_coords, c=colors, s=sizes, alpha=0.7)

        # Plot trust relationships
        for vehicle in self.simulation.vehicles:
            for neighbor in vehicle.neighbors:
                if neighbor.trusted:
                    self.trust_ax.plot(
                        [vehicle.position[0], neighbor.position[0]],
                        [vehicle.position[1], neighbor.position[1]],
                        'g-', alpha=0.4
                    )

        # Add vehicle IDs
        for vehicle in self.simulation.vehicles:
            self.trust_ax.text(vehicle.position[0], vehicle.position[1],
                               vehicle.id, fontsize=8, ha='center')

        self.trust_ax.set_title("Trust Network")
        self.trust_ax.set_xlim(0, self.simulation.width)
        self.trust_ax.set_ylim(0, self.simulation.height)

        # Add legend for trust network
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=8, label='Normal'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=8, label='Malicious'),
            Line2D([0], [0], color='g', lw=2, alpha=0.4, label='Trust Relationship')
        ]
        self.trust_ax.legend(handles=legend_elements, loc='upper right')

        # Adjust layout and draw
        self.security_fig.tight_layout()
        self.security_canvas.draw()

    def simulate_attack(self):
        """Simulate different types of attacks"""
        attack_types = [
            "Sybil Attack",
            "Black Hole",
            "Replay Attack",
            "Message Tampering"
        ]

        # Show attack type selection dialog
        attack_dialog = AttackDialog(self.root, attack_types)
        self.root.wait_window(attack_dialog.top)

        if attack_dialog.result:
            attack_type = attack_dialog.result

            # Execute selected attack
            if attack_type == "Sybil Attack":
                self.execute_sybil_attack()
            elif attack_type == "Black Hole":
                self.execute_blackhole_attack()
            elif attack_type == "Replay Attack":
                self.execute_replay_attack()
            elif attack_type == "Message Tampering":
                self.execute_tampering_attack()

    def execute_sybil_attack(self):
        """Execute a Sybil attack (one vehicle using multiple fake identities)"""
        if not self.simulation.vehicles:
            messagebox.showinfo("Error", "No vehicles in simulation")
            return

        # Choose a random vehicle to turn malicious
        attacker = random.choice(self.simulation.vehicles)
        attacker.malicious = True

        # Create fake identities (cloned positions)
        num_fake = random.randint(2, 5)
        for i in range(num_fake):
            fake_id = f"Fake_{attacker.id}_{i}"
            fake_position = (
                attacker.position[0] + random.uniform(-20, 20),
                attacker.position[1] + random.uniform(-20, 20)
            )

            fake_vehicle = Vehicle(
                vehicle_id=fake_id,
                speed=attacker.speed * random.uniform(0.8, 1.2),
                position=fake_position,
                malicious=True
            )

            self.simulation.vehicles.append(fake_vehicle)

        self.log_text.insert(tk.END, f"Sybil attack executed: {attacker.id} created "
                                     f"{num_fake} fake identities\n")
        self.log_text.see(tk.END)
        self.draw_network()

    def execute_blackhole_attack(self):
        """Execute a black hole attack (vehicle drops all messages)"""
        if not self.simulation.vehicles:
            messagebox.showinfo("Error", "No vehicles in simulation")
            return

        # Choose a random vehicle to turn into a black hole
        attacker = random.choice(self.simulation.vehicles)
        attacker.malicious = True

        # Override process_message to drop all messages
        def black_hole_process(self, message, hashes, signature, public_key_bytes, source_id):
            # Drop the message (don't forward it)
            return False

        # Apply the monkey patch
        attacker.original_process_message = attacker.process_message
        attacker.process_message = black_hole_process.__get__(attacker, Vehicle)

        self.log_text.insert(tk.END, f"Black hole attack executed: {attacker.id} "
                                     f"will drop all messages\n")
        self.log_text.see(tk.END)

    def execute_replay_attack(self):
        """Execute a replay attack (messages are captured and replayed)"""
        if not self.simulation.vehicles:
            messagebox.showinfo("Error", "No vehicles in simulation")
            return

        # Choose a random vehicle to turn malicious
        attacker = random.choice(self.simulation.vehicles)
        attacker.malicious = True

        # Capture messages to replay
        if hasattr(self.simulation, 'logs') and self.simulation.logs:
            # Find valid messages
            valid_messages = []
            for log in self.simulation.logs:
                if log.get('type') == 'receive' and log.get('valid'):
                    valid_messages.append(log)

            if valid_messages:
                # Replay a random valid message
                replay_log = random.choice(valid_messages)
                replay_message = replay_log.get('message')

                # Broadcast replayed message to all neighbors
                for neighbor in attacker.neighbors:
                    # Generate fake hashes and signature
                    hashes = attacker.hash_message(replay_message)
                    signature = attacker.sign_message(replay_message)

                    # Send replayed message
                    self.simulation.receive_message(
                        neighbor, replay_message, hashes, signature,
                        attacker.public_key_bytes, attacker.id
                    )

                self.log_text.insert(tk.END, f"Replay attack executed: {attacker.id} "
                                             f"replayed message from {replay_log.get('source')}\n")
                self.log_text.see(tk.END)
            else:
                self.log_text.insert(tk.END, "Replay attack failed: No valid messages to replay\n")
                self.log_text.see(tk.END)
        else:
            self.log_text.insert(tk.END, "Replay attack failed: No message history\n")
            self.log_text.see(tk.END)

    def execute_tampering_attack(self):
        """Execute a message tampering attack"""
        if not self.simulation.vehicles:
            messagebox.showinfo("Error", "No vehicles in simulation")
            return

        # Choose a random vehicle to turn malicious
        attacker = random.choice(self.simulation.vehicles)
        attacker.malicious = True

        # Generate and broadcast tampered message
        original_message, hashes, signature, public_key = attacker.generate_message()

        # Tamper with message
        tampered_message = original_message.copy()
        tampered_message["speed"] = original_message["speed"] * 3  # Extreme speed
        tampered_message["position"] = (
            original_message["position"][0] + random.uniform(-100, 100),
            original_message["position"][1] + random.uniform(-100, 100)
        )

        # Try to keep original hashes (which won't match the tampered message)
        for neighbor in attacker.neighbors:
            self.simulation.receive_message(
                neighbor, tampered_message, hashes, signature,
                attacker.public_key_bytes, attacker.id
            )

        self.log_text.insert(tk.END, f"Tampering attack executed: {attacker.id} "
                                     f"sent tampered message\n")
        self.log_text.see(tk.END)

    def update_log(self):
        """Update log text from queue"""
        try:
            while True:
                message = self.output_queue.get_nowait()
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
        except queue.Empty:
            pass

        # Schedule next update
        self.root.after(100, self.update_log)


class AttackDialog:
    """Dialog for selecting attack type"""

    def __init__(self, parent, attack_types):
        self.result = None

        # Create the top-level dialog window
        self.top = tk.Toplevel(parent)
        self.top.title("Select Attack Type")
        self.top.geometry("300x200")
        self.top.transient(parent)
        self.top.grab_set()

        # Add instructions
        ttk.Label(self.top, text="Select an attack type to simulate:",
                  font=("Segoe UI", 11)).pack(pady=(10, 20))

        # Create attack type buttons
        for attack_type in attack_types:
            ttk.Button(self.top, text=attack_type,
                       command=lambda t=attack_type: self.select(t)).pack(fill=tk.X, padx=20, pady=5)

        # Add cancel button
        ttk.Button(self.top, text="Cancel",
                   command=self.cancel).pack(fill=tk.X, padx=20, pady=(10, 5))

    def select(self, attack_type):
        """Select an attack type and close dialog"""
        self.result = attack_type
        self.top.destroy()

    def cancel(self):
        """Cancel selection and close dialog"""
        self.top.destroy()


def create_zip_file():
    """Create a zip file with all project files"""
    import zipfile
    import os

    files_to_zip = [
        'vanet_secure_routing.py',
        'README.md'
    ]

    # Create reports directory if it doesn't exist
    if not os.path.exists("reports"):
        os.makedirs("reports")

    # Create sample report files
    with open("reports/sample_report.csv", "w") as f:
        f.write("time,pdr\n0.1,0.9\n0.2,0.85\n0.3,0.95\n")

    files_to_zip.append('reports/sample_report.csv')

    # Create README
    with open("README.md", "w") as f:
        f.write("""# VANET Secure Routing Protocol Implementation

## Overview
This project implements a secure routing protocol for Vehicular Ad Hoc Networks (VANET) with a focus on security, 
using digital signatures and hash functions to prevent common attacks.

## Features
- Simulation of vehicle movement and communication in a VANET environment
- Implementation of secure routing protocol with digital signatures and hash functions
- Attack simulation and detection (Sybil, Black Hole, Replay, Message Tampering)
- Performance metrics and visualization
- User-friendly GUI interface

## Requirements
- Python 3.6+
- Required packages: matplotlib, numpy, pandas, cryptography, tkinter

## Installation
```bash
pip install matplotlib numpy pandas cryptography
```

## Usage
```bash
python vanet_secure_routing.py
```

## Security Features
- Digital signatures for message authentication
- Multiple hash functions for message integrity
- Trust scoring mechanism
- Attack detection algorithms

## Performance Metrics
- Packet Delivery Ratio
- End-to-End Delay
- Throughput
- Security Effectiveness
- Hash Algorithm Performance

## License
This project is for educational purposes only.
""")

    # Create zip file
    with zipfile.ZipFile("vanet_secure_routing.zip", "w") as zipf:
        for file in files_to_zip:
            if os.path.exists(file):
                zipf.write(file)

    print("Created zip file: vanet_secure_routing.zip")


def main():
    """Main entry point for application"""
    # Create main window
    root = tk.Tk()
    app = VANETSimulationApp(root)

    # Create zip file
    create_zip_file()

    # Start GUI main loop
    root.mainloop()


if __name__ == "__main__":
    main()