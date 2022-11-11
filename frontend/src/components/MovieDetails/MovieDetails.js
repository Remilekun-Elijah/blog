import React, { useEffect } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { useParams } from 'react-router-dom'
import { fetchAsyncShowOrMovie, getSelectedMovie, removeSelectedMovieOrShow } from '../../features/movies/showSlice'
import "./MovieDetails.scss"

export default function MovieDetails() {
  const { imdbId} = useParams()
  const dispatch = useDispatch()
  const data = useSelector(getSelectedMovie)

  console.log(data);
  useEffect(()=> {
    dispatch(fetchAsyncShowOrMovie(imdbId));
    dispatch(removeSelectedMovieOrShow())
  }, [])
  return (
    <div className='movie-section'>
      {Object.keys(data).length === 0 ? <h2 style={{textAlign: "center", color: "white"}}>Loading...</h2> :
      <>
      <div className="section-left">
        <div className="movie-title">
          {data.title}
        </div>
        <div className="movie-rating">
          <span>
            IMOB Rating <i className='fa fa-star'></i> : {data.imdbRating}
          </span>

          <span>
            IMOB Votes <i className='fa fa-thumbs-up'></i> : {data.imdbVotes}
          </span>

          <span>
            Runtime <i className='fa fa-film'></i> : {data.Runtime}
          </span>

          <span>
            Year <i className='fa fa-calender'></i> : {data.Year}
          </span>
        </div>
        <div className="movie-plot">{data.Plot}</div>

        <div className="movie-info">
          <div>
          <span> Director</span>
          <span> {data.Director}</span>
          </div>

          <div>
          <span> Stars</span>
          <span> {data.Actors}</span>
          </div>

          <div>
          <span> Genres</span>
          <span> {data.Genre}</span>
          </div>

          <div>
          <span> Language</span>
          <span> {data.Language}</span>
          </div>

          <div>
          <span> Awards</span>
          <span> {data.Awards}</span>
          </div>
        </div>
      </div>
      <div className="section-right">
        <img src={data.Poster} alt={data.Title}/>
      </div>
      </>
}
    </div>
  )
}
