import React from 'react'
import { useSelector } from 'react-redux'
import { getAllMovies } from '../../features/movies/movieSlice'
import { getAllShows } from '../../features/movies/showSlice'
import MovieCard from "../MovieCard/MovieCard"
import "./MovieListing.scss"

export default function MovieListing() {
  const movies = useSelector(getAllMovies)
  const shows = useSelector(getAllShows)

  return (
    <div className='movie-wrapper'>
      {movies?.Search?.length && shows?.Search?.length ? 
      <>
      <div className="movie-list">
        <h2>Movies</h2>
        <div className="movie-container">

      {movies.Response === "True" 
      ? movies.Search.map((data, key) => <MovieCard {...{ key, data }}/>) 
      : <div className='movies-error'>{movies.Error}</div>}

        </div>
      </div>

      <div className="movie-list">
        <h2>Shows</h2>
        <div className="movie-container">

      {shows.Response === "True" 
      ? shows.Search.map((data, key) => <MovieCard {...{ key, data }}/>) 
      : <div className='movies-error'>{shows.Error}</div>}

        </div>
      </div>
      </> : 
      <h2 style={{textAlign: "center", marginBottom: "10px", color: "white"}}>Loading...</h2>
}
    </div>
  )
}