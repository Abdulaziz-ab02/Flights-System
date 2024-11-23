import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class EmailService {

  
  constructor(private http: HttpClient) {}
  sendEmail(body:any): Observable<any> {
    return this.http.post('https://localhost:7117/api/Email', body);
  }
}
