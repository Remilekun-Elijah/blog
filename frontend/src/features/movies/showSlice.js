import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import API from "../../common/api";
import config from "../../utils/config";

export const fetchAsyncShows = createAsyncThunk("shows/fetchAsyncShows", async (_, {rejectWithValue}) => {
 const text = "friends"
 try{

  const res = await API.get(`${config.apiQuery}&s=${text}&type=series`)
  return res.data
 }
 catch (err) {
console.log(err.response);
  return rejectWithValue(err)
 }
})

export const fetchAsyncShowOrMovie = createAsyncThunk("shows/fetchAsyncShowOrMovie", async (id, {rejectWithValue}) => {
 try{

  const res = await API.get(`${config.apiQuery}&i=${id}&plot=full`)
  return res.data
 }
 catch (err) {
console.log(err.response);
  return rejectWithValue(err)
 }
})

const initialState = {
 shows: {},
 showOrMovie: {}
}

const showSlice = createSlice({
 name: 'shows',
 initialState,
 reducers: {
  removeSelectedMovieOrShow: (state) =>{
    state.showOrMovie = {}
  }
 },
 extraReducers: (builder) => {
  builder
  .addCase(fetchAsyncShows.pending, ()=> console.log("SHOWS PENDING..."))
  .addCase(fetchAsyncShows.fulfilled, (state, {payload}) => {
   console.log("SHOWS FULFILLED")
   return {...state, shows: payload}
  })
  .addCase(fetchAsyncShows.rejected, ()=> console.log("SHOWS REJECTED"))
 
 .addCase(fetchAsyncShowOrMovie.fulfilled, (state, {payload}) => {
  console.log("SHOWORMOVIE FULFILLED")
  return {...state, showOrMovie: payload}
 })
 .addCase(fetchAsyncShowOrMovie.rejected, ()=> console.log("SHOWORMOVIE REJECTED"))

}
})

export const {removeSelectedMovieOrShow} = showSlice.actions;
export const getAllShows = state => state.shows.shows
export const getSelectedMovie = state => state.shows.showOrMovie
export default showSlice.reducer