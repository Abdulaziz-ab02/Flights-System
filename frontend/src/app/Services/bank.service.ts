import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class BankService {

  constructor(private http:HttpClient) { }

  PaymentCheck(body:any): Observable<any>{
    return this.http.post('https://localhost:7117/api/Bank',body);
  }
}
