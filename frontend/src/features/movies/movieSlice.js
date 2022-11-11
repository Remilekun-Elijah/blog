import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import API from "../../common/api";
import config from "../../utils/config";

export const fetchAsyncMovies = createAsyncThunk("movies/fetchAsyncMovies", async (_, thunk)=>{
 
 const text = "Harry"
 try{
    const res = await API.get(`${config.apiQuery}&s=${text}&type=movie`)
    return res.data
 }
 catch(err) {
  console.error(err.response);
  return thunk.rejectWithValue(err.response.data)
 }
})

const initialState = {
 movies: {}
}

const movieSlice = createSlice({
 name: "movies",
 initialState,
 reducers: {
  addMovies: (state, {payload}) => {
   state.movies = payload;
  }
 },
 extraReducers: (builder) =>{
  builder.addCase(fetchAsyncMovies.pending, () => {
   console.log("MOVIES PENDING...");
  })
  .addCase(fetchAsyncMovies.fulfilled, (state, {payload}) => {
   console.log("MOVIES FULFILLED");
   return {...state, movies: payload}
  })
  .addCase(fetchAsyncMovies.rejected, () => {
   console.log("MOVIES REJECTED");
  })
 }
})

export const { addMovies } = movieSlice.actions;

export const getAllMovies = state => state.movies.movies;

export default movieSlice.reducer;