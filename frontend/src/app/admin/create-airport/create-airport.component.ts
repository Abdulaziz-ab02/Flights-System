// create-airport.component.ts
import { Component, AfterViewInit, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { AdminService } from 'src/app/Services/admin.service';
import * as L from 'leaflet';

@Component({
  selector: 'app-create-airport',
  templateUrl: './create-airport.component.html',
  styleUrls: ['./create-airport.component.css']
})
export class CreateAirportComponent implements OnInit, AfterViewInit {
  private map!: L.Map;
  private marker: L.Marker | null = null;
  private customIcon!: L.DivIcon;

  constructor(public admin: AdminService) {
    // Initialize the custom icon
    this.customIcon = L.divIcon({
      html: '<i class="fas fa-plane" style="color: #3f51b5; font-size: 24px;"></i>',
      className: 'custom-div-icon',
      iconSize: [30, 30],
      iconAnchor: [15, 15]
    });
  }

  createAirport: FormGroup = new FormGroup({
    airportname: new FormControl('', Validators.required),
    iatacode: new FormControl('', Validators.required),
    longitude: new FormControl('', Validators.required),
    latitude: new FormControl('', Validators.required),
    airportimage: new FormControl(),
    cityid: new FormControl('', Validators.required)
  });

  cities: { cityname: string, id: number }[] = [];

  ngOnInit(): void {
    this.loadCities();

    // Subscribe to form changes to update marker
    this.createAirport.get('latitude')?.valueChanges.subscribe(lat => {
      this.createAirport.get('longitude')?.value && this.updateMarkerFromForm();
    });

    this.createAirport.get('longitude')?.valueChanges.subscribe(lng => {
      this.createAirport.get('latitude')?.value && this.updateMarkerFromForm();
    });
  }

  ngAfterViewInit(): void {
    this.initMap();
  }

  private initMap(): void {
    // Initialize map with a default view
    this.map = L.map('map').setView([0, 0], 2);

    // Add a more detailed tile layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(this.map);

    // Add click handler to map
    this.map.on('click', (e: L.LeafletMouseEvent) => {
      const lat = e.latlng.lat.toFixed(6);
      const lng = e.latlng.lng.toFixed(6);

      this.createAirport.patchValue({
        latitude: lat,
        longitude: lng
      });

      this.updateMarker(e.latlng);
    });
  }

  private updateMarker(latlng: L.LatLng): void {
    if (this.marker) {
      this.map.removeLayer(this.marker);
    }

    // Create new marker with custom icon
    this.marker = L.marker(latlng, { icon: this.customIcon })
      .addTo(this.map)
      .bindPopup('Airport Location')
      .openPopup();

    // Add a pulsing effect to highlight the new location
    if (this.marker) {
      const el = this.marker.getElement();
      if (el) {
        el.style.animation = 'none';
        el.offsetHeight; // Trigger reflow
        el.style.animation = 'pulse 2s';
      }
    }
  }

  private updateMarkerFromForm(): void {
    const lat = parseFloat(this.createAirport.get('latitude')?.value);
    const lng = parseFloat(this.createAirport.get('longitude')?.value);

    if (!isNaN(lat) && !isNaN(lng)) {
      const latlng = L.latLng(lat, lng);
      this.updateMarker(latlng);
      this.map.setView(latlng, this.map.getZoom());
    }
  }

  loadCities() {
    this.admin.GetAllCiies().subscribe(
      (res: any[]) => {
        this.cities = res.map(cityObj => ({
          cityname: cityObj.cityname,
          id: cityObj.id
        }));
      },
      (err: any) => {
        console.error('Error loading cities:', err);
      }
    );
  }

  save() {
    this.admin.createAirport(this.createAirport.value);
  }

  uploadFile(file: any) {
    if (file.length == 0) return;
    let upload = <File>file[0];
    const formData = new FormData();
    formData.append('file', upload, upload.name);
    this.admin.uploadImage(formData);
  }
}