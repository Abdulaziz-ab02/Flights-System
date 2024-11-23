import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { AdminSharedModule } from './admin/admin-shared/admin-shared.module';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { GuestSharedModule } from './guest/guest-shared/guest-shared.module';
import { ToastrModule, ToastNoAnimation, ToastNoAnimationModule } from 'ngx-toastr';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { TokenInterceptor } from 'src/Interceptor/token.interceptor';
import { MatTableModule } from '@angular/material/table';



@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    GuestSharedModule,
    AdminSharedModule,
    BrowserAnimationsModule,
    ToastrModule.forRoot(),
    ToastNoAnimationModule.forRoot(),
    MatTableModule
  ],
  providers: [{
    provide:HTTP_INTERCEPTORS,
    useClass:TokenInterceptor,
     multi:true
    }],
  bootstrap: [AppComponent]
})
export class AppModule { }
