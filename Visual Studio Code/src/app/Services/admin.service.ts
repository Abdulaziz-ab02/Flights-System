import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { Observable } from 'rxjs';


@Injectable({
  providedIn: 'root'
})
export class AdminService {

  constructor(public http: HttpClient) { }


  users: any = [];
  UsersCount: number = 0;
  getAllUsers() {
    this.http.get('https://localhost:7117/api/User/GetAllUsers').subscribe(result => {
      this.users = result;
      this.UsersCount = this.users.length;

    }, err => {
      console.log(err.message)
    });
  }

  GetUsersWithPartners(): Observable<any> {
    return this.http.get("https://localhost:7117/api/User/GetUsersWithPartners");
  }

  GetPartnersByUser(id: number): Observable<any> {
    return this.http.get("https://localhost:7117/api/Partner/getPartnerByUserId/" + id);
  }



  airline: any = [];
  GetAllAirline() {
    this.http.get('https://localhost:7117/api/Airline').subscribe(result => {
      this.airline = result;

    }, err => {
      console.log(err.message)
    });
  }


  airport: any = [];
  AirportCount: number = 0;
  FetchAllAirports() {
    this.http.get('https://localhost:7117/api/Airport').subscribe(result => {
      this.airport = result;
      this.AirportCount = this.airport.length;
    }, err => {
      console.log(err.message)
    });
  }


  reservations: any = [];
  ReservationCount: number = 0;
  FetchAllReservations() {
    this.http.get('https://localhost:7117/api/Reservation').subscribe(result => {
      this.reservations = result;
      this.ReservationCount = this.reservations.length;

    }, err => {
      console.log(err.message)
    });
  }



  //Airport Page
  deleteAirport(id: number) {
    this.http.delete("https://localhost:7117/api/Airport/DeleteAirport/" + id).subscribe(result => {
      console.log("deleted")
    }, err => { console.log("error") })
    window.location.reload();
  }


  createAirport(bod: any) {
    bod.airportimage = this.img;
    this.http.post("https://localhost:7117/api/Airport/CreateAirport", bod).subscribe(res => {
      console.log("airport created");
    }, err => { console.log("try again"); })
    window.location.reload();
  }

  updateAirport(bod: any) {
    bod.airportimage = this.img;
    this.http.put("https://localhost:7117/api/Airport/UpdateAirport", bod).subscribe(res => {
      console.log("updated")
    }, err => { console.log("error") })
    window.location.reload();
  }

  // Return Observable for the cities
  GetAllCiies(): Observable<string[]> {
    return this.http.get<string[]>('https://localhost:7117/api/City/GetAllCities');
  }

  img: any;
  uploadImage(file: FormData) {
    this.http.post("https://localhost:7117/api/Airport/uploadImage", file).subscribe((res: any) => {
      this.img = res.airportimage;
    }, err => { console.log("error") })
  }





  deleteTestimonial(id: number) {
    this.http.delete('https://localhost:7117/api/Testimonial/DeleteTestimonial/' + id).subscribe(
      result => {
        console.log('the testimonial is deleted');
      }, err => {
        console.log(err.message)
      });
    window.location.reload();
  }


  UpdateTestimonial(id: number, status: string) {
    //debugger

    this.http.put('https://localhost:7117/api/Testimonial/ChangeTestimonialStatus/' + id + '/' + status, null).subscribe(
      (resp) => {
        console.log('Testimonial status updated')
      }, err => {
        console.log('Error')
      })
    window.location.reload();
  }




  // admin.service.ts
  changeAirlineStatus(id: number, status: string): Observable<any> {
    const url = `https://localhost:7117/api/Airline/ChangeAirlineActivationStatus/${id}/${status}`;
    return this.http.put(url, null);
  }

  deleteAirline(id: number) {
    this.http.delete("https://localhost:7117/api/Airline/deleteAirline/" + id).subscribe(result => {
      console.log("deleted");
    }, err => { console.log("error") })
    window.location.reload();
  }

  SearchReservations(body: any): Observable<any> {
    return this.http.post<any[]>('https://localhost:7117/api/Reservation/SearchReservation', body);
  }







  homeImage: any;
  uploadAttachmentHome(file: FormData) {
    this.http.post('https://localhost:7117/api/Home/uploadImage', file).subscribe(
      (resp: any) => {
        this.homeImage = resp.homeimage;
        console.log('image uploaded')
      }, err => {
        console.log('Error')
      })
  }
  UpdateHomePage(body: any) {
    body.homeimage = this.homeImage;
    this.http.put('https://localhost:7117/api/Home/UpdateHome', body).subscribe(result => {
      console.log('home page updated')
    }, err => {
      console.log(err.message)
    });
    window.location.reload();
  }



  aboutImage: any;
  uploadAttachmentAbout(file: FormData) {
    this.http.post('https://localhost:7117/api/About/uploadImage', file).subscribe(
      (resp: any) => {
        this.aboutImage = resp.aboutimage;
        console.log('image uploaded')
      }, err => {
        console.log('Error')
      })
  }
  UpdateAboutInfo(body: any) {
    body.aboutimage = this.aboutImage;
    this.http.put('https://localhost:7117/api/About/UpdateAbout', body).subscribe(result => {
      console.log('about page updated')
    }, err => {
      console.log(err.message)
    });
    window.location.reload();
  }



  UpdateContactInfo(body: any) {
    this.http.put('https://localhost:7117/api/Contact/UpdateContact', body).subscribe(result => {
      console.log('contact page updated')
    }, err => {
      console.log(err.message)
    });
    window.location.reload();
  }

  countries: any[] = [];
  CountriesCount: number = 0;

  getAllCountries() {
    this.http.get<any[]>('https://localhost:7117/api/Country/GetAllCountries').subscribe(result => {
      this.countries = result;
      this.CountriesCount = this.countries.length;

    }, err => {
      console.log('Error fetching countries:', err.message);
    });
  }

  createCountry(country: any) {
    return this.http.post('https://localhost:7117/api/Country/CreateCountry', country).subscribe(res => {
      console.log("Country created:", res);
      window.location.reload();
    }, err => {
      console.log("Error creating country:", err.message);
    });
  }

  updateCountry(country: any) {
    return this.http.put('https://localhost:7117/api/Country/UpdateCountry', country).subscribe(res => {
      console.log("Country updated:", res);
      window.location.reload();
    }, err => {
      console.log("Error updating country:", err.message);
    });
  }

  deleteCountry(id: number) {
    return this.http.delete(`https://localhost:7117/api/Country/DeleteCountry/${id}`).subscribe(result => {
      console.log("Country deleted:", result);
      window.location.reload();
    }, err => {
      console.log("Error deleting country:", err.message);
    });
  }



  CreateCity(city: any) {
    return this.http.post('https://localhost:7117/api/City/CreateCity', city).subscribe(res => {
      console.log("city created:", res);
      window.location.reload();
    }, err => {
      console.log("Error creating cities:", err.message);
    });
  }

  UpdateCity(city: any) {
    city.cityimage = this.cityImage;
    return this.http.put('https://localhost:7117/api/City/UpdateCity', city).subscribe(res => {
      console.log("City updated:", res);
      window.location.reload();
    }, err => {
      console.log("Error updating City:", err.message);
    });
  }

  DeleteCity(id: number) {
    return this.http.delete(`https://localhost:7117/api/City/DeleteCity/${id}`).subscribe(result => {
      console.log("City deleted:", result);
      window.location.reload();
    }, err => {
      console.log("Error deleting City:", err.message);
    });
  }
  getEntityCounts(): Observable<any> {
    return this.http.get('https://localhost:7117/api/Reservation/entity-counts');
  }
  GetAllCountries(): Observable<any[]> {
    return this.http.get<any[]>('https://localhost:7117/api/Country/GetAllCountries');
  }

  cityImage: any;
  uploadAttachmentCity(file: FormData) {
    this.http.post('https://localhost:7117/api/City/uploadImage', file).subscribe(
      (resp: any) => {
        this.cityImage = resp.cityimage;
        console.log('image uploaded')
      }, err => {
        console.log('Error')
      })
  }


  //degree page 

  GetAllDegrees(): Observable<any[]> {
    return this.http.get<any[]>('https://localhost:7117/api/Degree/GetAllDegrees');
  }




  updateDegree(body: any): Observable<any> {
    return this.http.put<any>("https://localhost:7117/api/Degree/UpdateDegree", body);
  }

  createDegree(body: any): Observable<any> {
    return this.http.post("https://localhost:7117/api/Degree/CreateDegree", body);
  }


  deleteDegree(id: number): Observable<any> {
    return this.http.delete(`https://localhost:7117/api/Degree/DeleteDegree/${id}`);
  }




  //degree facility

  GetAllFacilitesByDegree(id: number): Observable<any> {
    return this.http.get('https://localhost:7117/api/Flight/GetAllFacilitesByDegreeId/' + id);
  }



  getAllContactMessages(): Observable<any> {
    return this.http.get("https://localhost:7117/api/ContactMessage");
  }
  CreateContactMessage(body: any): Observable<any> {
    return this.http.post("https://localhost:7117/api/ContactMessage/CreateContactMessage", body);
  }

  GetAvailableFacilitiesForDegree(degreeId: number) {
    return this.http.get<any[]>(`https://localhost:7117/api/DegreeFacility/GetAvailableFacilitiesForDegree/${degreeId}`);
  }

  AddFacilityToDegree(degreeFacility: { degreeId: number; facilityId: number }): Observable<any> {
    return this.http.post('https://localhost:7117/api/DegreeFacility/CreateDegreeFacility', degreeFacility);
  }


  DeleteDegreeFacility(id: number): Observable<void> {
    return this.http.delete<void>(`https://localhost:7117/api/DegreeFacility/DeleteDegreeFacility/${id}`);
  }


  //report


  GetMonthlyTotalBenefits(month: number, year: number): Observable<any[]> {
    return this.http.get<any[]>(`https://localhost:7117/api/Reservation/MonthlyBenefits/${month}/${year}`);
  }

  GetAnnualTotalBenefits(year: number): Observable<any[]> {
    return this.http.get<any[]>(`https://localhost:7117/api/Reservation/AnnualBenefits/${year}`);
  }


}