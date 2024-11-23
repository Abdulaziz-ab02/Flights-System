import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class HomeService {

  constructor(public http: HttpClient) { }


  getAllTestimonials():Observable<any> {
    return this.http.get('https://localhost:7117/api/Testimonial');
  }


  homePage: any = [];
  getHomePage() {
    this.http.get('https://localhost:7117/api/Home').subscribe(result => {
      this.homePage = result;

    }, err => {
      console.log(err.message)
    });
  }


  contactInfo: any = [];
  getContactInfo() {
    this.http.get('https://localhost:7117/api/Contact').subscribe(result => {
      this.contactInfo = result;

    }, err => {
      console.log(err.message)
    });
  }


  aboutPage: any = [];
  getAboutInfo() {
    this.http.get('https://localhost:7117/api/About').subscribe(result => {
      this.aboutPage = result;

    }, err => {
      console.log(err.message)
    });
  }


  userProfileInfo: any;
  getUserProfileInfo(userId: any) {
    this.http.get('https://localhost:7117/api/User/getUserById/' + userId).subscribe(
      result => {
        this.userProfileInfo = result;
        console.log("USERID", userId)
        console.log("RESULT", result)
      }, err => {
        console.log('no cant bring data for the user')
      });
  }


  airlineProfileInfo: any;
  getAirlineProfileInfo(airId: any) {
    this.http.get('https://localhost:7117/api/Airline/GetAirlineById/' + airId).subscribe(
      result => {
        this.airlineProfileInfo = result;
      }, err => {
        console.log(err.message)
      });
  }



  CreateTestimonial(body: any) {
    this.http.post('https://localhost:7117/api/Testimonial/CreateTestimonial', body).subscribe(
      resp => {
        console.log('Testimonial created')
      }, err => {
        console.log(err.message)
      });
  }

  getUserInfo(id:any):Observable<any>{
    return this.http.get('https://localhost:7117/api/User/getUserById/' + id);
  }



  userReservations: any = [];
  getReservationsByUser(id: any) {
    this.http.get('https://localhost:7117/api/Reservation/FetchReservationByUserID/' + id).subscribe(
      result => {
        this.userReservations = result;
      }, err => {
        console.log(err.message)
      });
  }


}
