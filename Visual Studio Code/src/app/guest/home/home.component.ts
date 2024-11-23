import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { Router } from '@angular/router';
import { HomeService } from 'src/app/Services/home.service';
import { state } from '@angular/animations';
import { Token } from '@angular/compiler';
/* handleHomeFlights(flights: any[]) {
  this.router.navigate(['/flights'], { state: { flights } });
}*/
@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  constructor(public home: HomeService, private router: Router, public dialog: MatDialog) { }

  @ViewChild('callCreateDailog') createDialog !: TemplateRef<any>;

  isLoggedIn: boolean = false;
  partners: number = 0;
  flight: any[] = [];
  testimonials: any = [];


  ngOnInit(): void {
    this.FetchTestemonials();
    this.home.getHomePage();
    this.home.getContactInfo();
    const token = localStorage.getItem('token');
    //if the user is loggen in 
    if (token) {
      this.isLoggedIn = true;
    }

  }
  // Re-initialize carousel or any required script here

  FetchTestemonials() {
    this.home.getAllTestimonials().subscribe((res) => {
      //this.testimonials = res;

      // Shuffle the testimonials array
      const approvedTestimonials = res.filter((testimonial: any) => testimonial.testimonialstatus === 'Approved');
      this.testimonials = this.shuffle(approvedTestimonials);


      // Limit the array to 3 testimonials
      this.testimonials = this.testimonials.slice(0, 3);
    },
      (error) => {
        console.log(`There was an error while trying to fetch the testemonials data error
      message: ${error} :(`);
      })
  }
  shuffle(array: any[]) {
    let currentIndex = array.length, randomIndex, temporaryValue;

    // While there remain elements to shuffle
    while (currentIndex !== 0) {
      // Pick a remaining element
      randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;

      // And swap it with the current element
      temporaryValue = array[currentIndex];
      array[currentIndex] = array[randomIndex];
      array[randomIndex] = temporaryValue;
    }

    return array;
  }


  handlePartnersChanges(partners: number) {
    this.partners = partners
  }
  handleHomeFlights(flights: any[]) {
    this.flight = flights
    console.log(`Flights In Home page: ${flights} :)`);
    this.router.navigate(['/flights'], { state: { flights: this.flight, partners: this.partners } });
  }



  createTestimonial: FormGroup = new FormGroup({
    testimonialcontent: new FormControl('', Validators.required),
    rating: new FormControl('', [Validators.min(1), Validators.max(5)]),
    testimonialdate: new FormControl(),
    testimonialstatus: new FormControl(),
    userid: new FormControl()
  })

  openCreateDialog() {
    const currentDate = new Date().toISOString().split('T')[0]; // Get current date
    this.createTestimonial.controls['testimonialdate'].setValue(currentDate);

    let user: any = localStorage.getItem('user')
    user = JSON.parse(user)
    this.createTestimonial.controls['userid'].setValue(user.userid)
    this.createTestimonial.controls['testimonialstatus'].setValue('Pending')


    console.log('Testimonial Date:', this.createTestimonial.controls['testimonialdate'].value);
    console.log('User ID:', this.createTestimonial.controls['userid'].value);
    console.log('Testimonial Status:', this.createTestimonial.controls['testimonialstatus'].value);


    this.dialog.open(this.createDialog)
  }

  save() {
    this.home.CreateTestimonial(this.createTestimonial.value);
    window.location.reload();
  }

  cancel() {
    this.dialog.closeAll();
    window.location.reload();
  }

}













