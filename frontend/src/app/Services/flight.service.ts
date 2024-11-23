import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class FlightService {

  constructor(public http: HttpClient) { }

  SearchForFlight(body: any): Observable<any> {
    return this.http.post('https://localhost:7117/api/Flight/FetchFlightBasedOnUserSearch', body);
  }

  GetAllCiies(): Observable<string[]> {
    return this.http.get<string[]>('https://localhost:7117/api/City/GetAllCities');
  }
  GetAllDegrees(): Observable<string[]> {
    return this.http.get<string[]>('https://localhost:7117/api/Degree/GetAllDegrees');
  }

  GetAllFacilitesByDegree(id: number): Observable<any> {
    return this.http.get('https://localhost:7117/api/Flight/GetAllFacilitesByDegreeId/' + id);
  }

  GetAllFlightsByAirlineID(id: number): Observable<any> {
    return this.http.get('https://localhost:7117/api/Flight/GetAllFlightsByAirlineID/' + id);
  }

  CreateFlight(flight: any): Observable<any> {
    return this.http.post('https://localhost:7117/api/Flight/CreateFlight', flight);
  }

  DeleteFlight(id: number): Observable<any> {
    return this.http.delete('https://localhost:7117/api/Flight/DeleteFlight/' + id);
  }

  UpdateFlight(flight: any): Observable<any> {
    return this.http.put('https://localhost:7117/api/Flight/UpdateFlight', flight);
  }

  CreatePartner(body: any): Observable<any> {
    return this.http.post('https://localhost:7117/api/Partner/CreatePartner', body);
  }

  CreateReservation(body: any): Observable<any> {
    return this.http.post('https://localhost:7117/api/Reservation/CreateReservation', body);
  }

  FetchAllAirports(): Observable<any> {
    return this.http.get('https://localhost:7117/api/Airport');
  }

  FetchAllDegrees(): Observable<any> {
    return this.http.get('https://localhost:7117/api/Degree/GetAllDegrees');
  }
  FetchFlightByFlightID(flightId: any): Observable<any> {
    return this.http.get(`https://localhost:7117/api/Flight/FetchFlightByFlightNumber?flightNumber=${flightId}`);
  }

  getAllAirlines(): Observable<any> {
    return this.http.get("https://localhost:7117/api/Airline");
  }



  getAllFacilities(): Observable<any> {
    return this.http.get("https://localhost:7117/api/Facility");
  }

  CreateFacility(body: any): Observable<any> {
    return this.http.post("https://localhost:7117/api/Facility/CreateFacility", body);
  }

  UpdateFacility(body: any): Observable<any> {
    return this.http.put("https://localhost:7117/api/Facility/UpdateFacility", body);
  }

  DeleteFacility(id: any): Observable<any> {
    return this.http.delete("https://localhost:7117/api/Facility/DeleteFacility/" + id);
  }



  FetchReservationsByAirline(id: any): Observable<any> {
    return this.http.get("https://localhost:7117/api/Reservation/FetchReservationsByAirline/" + id);
  }

}
