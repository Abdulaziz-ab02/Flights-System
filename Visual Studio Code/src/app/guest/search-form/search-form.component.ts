import { Component, EventEmitter, Output } from '@angular/core';
import { FormControl, FormGroup } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { FlightService } from 'src/app/Services/flight.service';

@Component({
  selector: 'app-search-form',
  templateUrl: './search-form.component.html',
  styleUrls: ['./search-form.component.css']
})
export class SearchFormComponent {
  @Output() flightsFound = new EventEmitter<any[]>();
  @Output() partnerCount = new EventEmitter<number>();
  cities: { cityname: string, id: number }[] = [];  
  degree: { degreename: string, id: number }[] = [];  
  filteredDepartureCities: { cityname: string, id: number }[] = []; 
  filteredDestinationCities: { cityname: string, id: number }[] = []; 
  selectedDepartureCity: string = ''; 
  selectedDestinationCity: string = ''; 
  flights: any[] = []; 
  Facilites: any[] = [];
  passengerCount: number = 0;

  constructor(private flight: FlightService, private router: Router, private activatedRoute: ActivatedRoute) {}
  
  ngOnInit() {
    this.loadCities(); 
    this.loadDegrees();
  }

  onPassengerChange(event: Event) {
    const selectElement = event.target as HTMLSelectElement;
    this.passengerCount = +selectElement.value;
    this.partnerCount.emit(this.passengerCount);
  }

  loadCities() {
    this.flight.GetAllCiies().subscribe(
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
  loadDegrees(){
    this.flight.GetAllDegrees().subscribe((res:any[]) => {
      this.degree = res.map(degreeObj => ({
        degreename: degreeObj.degreename,
        id:degreeObj.id
      }));
    },
  (error) => {
    console.log('There was an error while tring to hit Degree API :(');
  })
  }

  GetAllFacilitesByDegreeId(id: number) {
    console.log('Fetching facilities for degree ID:', id);
    this.flight.GetAllFacilitesByDegree(id).subscribe(
      (res: any[]) => {
        this.Facilites = res.map((facility: any) => ({
          facilityname: facility.facilityname
        }));
      },
      (err: any) => {
        console.error('Error fetching facilities:', err);
      }
    );
  }

  filterDepartureOptions(event: Event) {
    const input = event.target as HTMLInputElement;
    const searchTerm = input.value.toLowerCase();
    this.filteredDepartureCities = this.cities.filter(city =>
      city.cityname.toLowerCase().includes(searchTerm)
    );
  }

  filterDestinationOptions(event: Event) {
    const input = event.target as HTMLInputElement;
    const searchTerm = input.value.toLowerCase();
    this.filteredDestinationCities = this.cities.filter(city =>
      city.cityname.toLowerCase().includes(searchTerm)
    );
  }

  searchForm: FormGroup = new FormGroup({
    departuredate: new FormControl(),
    departurePlaceId: new FormControl(),
    destenationPlaceId: new FormControl(),
    degreenameId: new FormControl()
  });

  SearchInput() {
    console.log(this.degree);
    console.log('Search initiated with form data:', this.searchForm.value);
  
    this.flight.SearchForFlight(this.searchForm.value).subscribe(
      async (res: any[]) => {
        this.flights = res;
        console.log('Search results:', this.flights);
  
        // Fetch facilities for each flight and wait for all to complete
        const facilityPromises = this.flights.map(async (flight) => {
          const facilities = await this.flight.GetAllFacilitesByDegree(flight.degreeId).toPromise();
          flight.facilities = facilities.map((facility: any) => ({
            facilityname: facility.facilityname
          }));
        });
  
        // Wait until all facility fetches are complete
        await Promise.all(facilityPromises);
  
        // Emit the results after facilities are populated
        this.flightsFound.emit(this.flights);
      },
      (err: any) => {
        console.error('Error occurred during search:', err);
      }
    );
  }
  
  

  selectDepartureCity(city: { cityname: string, id: number } | null) {
    if (city === null) {
      this.selectedDepartureCity = 'None';
      this.searchForm.controls['departurePlaceId'].setValue(null);
    } else {
      this.selectedDepartureCity = city.cityname;
      this.searchForm.controls['departurePlaceId'].setValue(city.id);
    }
    this.filteredDepartureCities = []; // Hide dropdown after selection
  }

  // Method to handle selecting a destination city, including the "None" option
  selectDestinationCity(city: { cityname: string, id: number } | null) {
    if (city === null) {
      this.selectedDestinationCity = 'None';
      this.searchForm.controls['destenationPlaceId'].setValue(null);
    } else {
      this.selectedDestinationCity = city.cityname;
      this.searchForm.controls['destenationPlaceId'].setValue(city.id);
    }
    this.filteredDestinationCities = []; // Hide dropdown after selection
  }
}
